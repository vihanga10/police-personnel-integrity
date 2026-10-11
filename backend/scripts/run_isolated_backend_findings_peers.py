"""Disposable witnessed recovery plus Fabric/local EVM tests. No live deployment."""
import argparse, hashlib, io, json, os, re, shutil, subprocess, tarfile, tempfile, time
from pathlib import Path
from uuid import uuid4

FABRIC='2.5.16'
POLICY='PPI_DISPOSABLE_FINDINGS_FABRIC_V1'
LABEL='ppi.findings.integration'

def captured_env():
    # Do not inherit peer/CA/MSP/Docker endpoint or SDK credential configuration.
    allowed=('PATH','HOME','TMPDIR','DOCKER_CONFIG','LANG','LC_ALL')
    return {k:os.environ[k] for k in allowed if k in os.environ}

def package_cc():
    def archive(files):
        b=io.BytesIO()
        with tarfile.open(fileobj=b,mode='w:gz') as t:
            for name,data in files.items():
                entry=tarfile.TarInfo(name);entry.size=len(data);entry.mode=0o600;t.addfile(entry,io.BytesIO(data))
        return b.getvalue()
    connection=json.dumps(dict(address='findings:9999',dial_timeout='10s',tls_required=False)).encode()
    return archive({'metadata.json':json.dumps(dict(type='ccaas',label='findings_fixture')).encode(),'code.tar.gz':archive({'connection.json':connection})})

def configs(root):
    crypto='''OrdererOrgs:
  - Name: Orderer
    Domain: example.com
    EnableNodeOUs: true
    Specs:
      - Hostname: orderer
PeerOrgs:
  - Name: Org1
    Domain: org1.example.com
    EnableNodeOUs: true
    Template:
      Count: 1
    Users:
      Count: 1
  - Name: Org2
    Domain: org2.example.com
    EnableNodeOUs: true
    Template:
      Count: 1
    Users:
      Count: 1
'''
    organizations=[]
    for i in (1,2):
        organizations.append(f'''  - &Org{i}
    Name: Org{i}MSP
    ID: Org{i}MSP
    MSPDir: /work/run/crypto/peerOrganizations/org{i}.example.com/msp
    Policies:
      Readers:
        Type: Signature
        Rule: "OR('Org{i}MSP.admin', 'Org{i}MSP.peer', 'Org{i}MSP.client')"
      Writers:
        Type: Signature
        Rule: "OR('Org{i}MSP.admin', 'Org{i}MSP.client')"
      Admins:
        Type: Signature
        Rule: "OR('Org{i}MSP.admin')"
      Endorsement:
        Type: Signature
        Rule: "OR('Org{i}MSP.peer')"
    AnchorPeers:
      - Host: peer0.org{i}.example.com
        Port: {7051 if i==1 else 9051}
''')
    config='''Organizations:
  - &OrdererOrg
    Name: OrdererMSP
    ID: OrdererMSP
    MSPDir: /work/run/crypto/ordererOrganizations/example.com/msp
    Policies:
      Readers:
        Type: Signature
        Rule: "OR('OrdererMSP.member')"
      Writers:
        Type: Signature
        Rule: "OR('OrdererMSP.member')"
      Admins:
        Type: Signature
        Rule: "OR('OrdererMSP.admin')"
    OrdererEndpoints:
      - orderer.example.com:7050
'''+''.join(organizations)+'''
Capabilities:
  Channel: &ChannelCapabilities
    V2_0: true
  Orderer: &OrdererCapabilities
    V2_0: true
  Application: &ApplicationCapabilities
    V2_0: true
Application: &ApplicationDefaults
  Organizations:
  Policies:
    Readers:
      Type: ImplicitMeta
      Rule: "ANY Readers"
    Writers:
      Type: ImplicitMeta
      Rule: "ANY Writers"
    Admins:
      Type: ImplicitMeta
      Rule: "MAJORITY Admins"
    LifecycleEndorsement:
      Type: ImplicitMeta
      Rule: "MAJORITY Endorsement"
    Endorsement:
      Type: ImplicitMeta
      Rule: "MAJORITY Endorsement"
  Capabilities: *ApplicationCapabilities
Orderer: &OrdererDefaults
  OrdererType: etcdraft
  Addresses:
    - orderer.example.com:7050
  EtcdRaft:
    Consenters:
      - Host: orderer.example.com
        Port: 7050
        ClientTLSCert: /work/run/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt
        ServerTLSCert: /work/run/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt
  BatchTimeout: 1s
  BatchSize:
    MaxMessageCount: 10
    AbsoluteMaxBytes: 99 MB
    PreferredMaxBytes: 512 KB
  Organizations:
  Policies:
    Readers:
      Type: ImplicitMeta
      Rule: "ANY Readers"
    Writers:
      Type: ImplicitMeta
      Rule: "ANY Writers"
    Admins:
      Type: ImplicitMeta
      Rule: "MAJORITY Admins"
    BlockValidation:
      Type: ImplicitMeta
      Rule: "ANY Writers"
  Capabilities: *OrdererCapabilities
Channel: &ChannelDefaults
  Policies:
    Readers:
      Type: ImplicitMeta
      Rule: "ANY Readers"
    Writers:
      Type: ImplicitMeta
      Rule: "ANY Writers"
    Admins:
      Type: ImplicitMeta
      Rule: "MAJORITY Admins"
  Capabilities: *ChannelCapabilities
Profiles:
  FindingsFixture:
    <<: *ChannelDefaults
    Orderer:
      <<: *OrdererDefaults
      Organizations:
        - *OrdererOrg
    Application:
      <<: *ApplicationDefaults
      Organizations:
        - *Org1
        - *Org2
'''
    (root/'crypto.yaml').write_text(crypto);(root/'configtx.yaml').write_text(config)

def plan(root,run_id,ccid):
    if not re.fullmatch('ppi-findings-[0-9a-f]{24}',run_id):raise ValueError('Unique isolated project required')
    bind=[str(root)+':/work/run']
    ca=lambda n:f'/work/run/crypto/peerOrganizations/org{n}.example.com/peers/peer0.org{n}.example.com/tls/ca.crt'
    order='/work/run/crypto/ordererOrganizations/example.com/orderers/orderer.example.com'
    def service(image,command,environment=None,aliases=None,user=None):
        v=dict(image=image,command=command,volumes=bind,labels={LABEL:run_id},networks={'fixture':{'aliases':aliases or []}})
        if image.startswith('hyperledger/fabric-'):v['platform']='linux/amd64'
        if environment:v['environment']=environment
        if user:v['user']=user
        return v
    services={'orderer':service('hyperledger/fabric-orderer:'+FABRIC,['orderer'],{
        'ORDERER_GENERAL_LISTENADDRESS':'0.0.0.0','ORDERER_GENERAL_LISTENPORT':'7050',
        'ORDERER_GENERAL_LOCALMSPID':'OrdererMSP','ORDERER_GENERAL_LOCALMSPDIR':order+'/msp',
        'ORDERER_GENERAL_BOOTSTRAPMETHOD':'none','ORDERER_CHANNELPARTICIPATION_ENABLED':'true',
        'ORDERER_GENERAL_TLS_ENABLED':'true','ORDERER_GENERAL_TLS_PRIVATEKEY':order+'/tls/server.key','ORDERER_GENERAL_TLS_CERTIFICATE':order+'/tls/server.crt',
        'ORDERER_GENERAL_TLS_ROOTCAS':'['+order+'/tls/ca.crt]',
        'ORDERER_GENERAL_CLUSTER_CLIENTCERTIFICATE':order+'/tls/server.crt','ORDERER_GENERAL_CLUSTER_CLIENTPRIVATEKEY':order+'/tls/server.key',
        'ORDERER_GENERAL_CLUSTER_ROOTCAS':'['+order+'/tls/ca.crt]',
        'ORDERER_ADMIN_LISTENADDRESS':'0.0.0.0:7053','ORDERER_ADMIN_TLS_ENABLED':'true','ORDERER_ADMIN_TLS_CLIENTAUTHREQUIRED':'true','ORDERER_ADMIN_TLS_PRIVATEKEY':order+'/tls/server.key',
        'ORDERER_ADMIN_TLS_CERTIFICATE':order+'/tls/server.crt','ORDERER_ADMIN_TLS_CLIENTROOTCAS':'['+order+'/tls/ca.crt]',
    },['orderer.example.com'])}
    for i in (1,2):
        port=7051 if i==1 else 9051;peer=f'peer0.org{i}.example.com';base=f'/work/run/crypto/peerOrganizations/org{i}.example.com/peers/{peer}'
        services['peer'+str(i)]=service('hyperledger/fabric-peer:'+FABRIC,['peer','node','start'],{
            'CORE_PEER_ID':peer,'CORE_PEER_ADDRESS':peer+':'+str(port),'CORE_PEER_LISTENADDRESS':'0.0.0.0:'+str(port),
            'CORE_PEER_CHAINCODEADDRESS':peer+':'+str(port+1),'CORE_PEER_CHAINCODELISTENADDRESS':'0.0.0.0:'+str(port+1),
            'CORE_PEER_GOSSIP_EXTERNALENDPOINT':peer+':'+str(port),'CORE_PEER_GOSSIP_USELEADERELECTION':'false','CORE_PEER_GOSSIP_ORGLEADER':'true',
            'CORE_PEER_LOCALMSPID':f'Org{i}MSP','CORE_PEER_MSPCONFIGPATH':base+'/msp',
            'CORE_PEER_TLS_ENABLED':'true','CORE_PEER_TLS_CLIENTAUTHREQUIRED':'true','CORE_PEER_TLS_CERT_FILE':base+'/tls/server.crt',
            'CORE_PEER_TLS_KEY_FILE':base+'/tls/server.key','CORE_PEER_TLS_ROOTCERT_FILE':base+'/tls/ca.crt',
            'CORE_PEER_TLS_CLIENTROOTCAS_FILES':'/work/run/tls-client/peer-client-roots.pem',
            'CORE_CHAINCODE_EXTERNALBUILDERS':json.dumps([dict(name='ccaas_builder',path='/opt/hyperledger/ccaas_builder',propagateEnvironment=['CHAINCODE_AS_A_SERVICE_BUILDER_CONFIG'])]),
        },[peer])
    for name in ('orderer','peer1','peer2'):
        services[name]['tmpfs']=['/var/hyperledger/production']
    uid=f'{os.getuid()}:{os.getgid()}'
    services['findings']=service(run_id+':sdk',['node','/work/fabric/integration/node_modules/fabric-shim/cli.js','server','--module-path','/work/fabric/findings-chaincode',
        '--chaincode-address','0.0.0.0:9999','--chaincode-id',ccid],user=uid)
    services['tools']=service('hyperledger/fabric-tools:'+FABRIC,['sleep','infinity'],{'FABRIC_CFG_PATH':'/etc/hyperledger/fabric'},user=uid)
    services['runner']=service(run_id+':sdk',['node','/work/fabric/integration/findings-peer-check.js'],{'PPI_TEST_ROOT':'/work/run'},user=uid)
    return {'services':services,'networks':{'fixture':{'name':run_id,'labels':{LABEL:run_id}}}}

def peer_env(i):
    org=f'/work/run/crypto/peerOrganizations/org{i}.example.com';host=f'peer0.org{i}.example.com'
    return dict(CORE_PEER_LOCALMSPID=f'Org{i}MSP',CORE_PEER_MSPCONFIGPATH=org+f'/users/Admin@org{i}.example.com/msp',
        CORE_PEER_ADDRESS=host+':'+str(7051 if i==1 else 9051),CORE_PEER_TLS_ENABLED='true',CORE_PEER_TLS_ROOTCERT_FILE=org+'/peers/'+host+'/tls/ca.crt',
        CORE_PEER_TLS_CLIENTCERT_FILE='/work/run/tls-client/cert.pem',CORE_PEER_TLS_CLIENTKEY_FILE='/work/run/tls-client/key.pem',
        CORE_PEER_TLS_CLIENTAUTHREQUIRED='true')

def owned(records,run_id):
    return all(r.get('Config',{}).get('Labels',{}).get(LABEL)==run_id for r in records)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--suite',choices=('backend-peers',),default='backend-peers');args=ap.parse_args()
    repo=Path(__file__).resolve().parents[2];env=captured_env();phase='preflight';root=None;run_id=None;started=False;clean=False
    try:
        subprocess.run(['docker','info'],check=True,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        subprocess.run(['docker','compose','version'],check=True,env=env,stdout=subprocess.DEVNULL,timeout=30)
        run_id='ppi-findings-'+uuid4().hex[:24]
        root=Path(tempfile.mkdtemp(prefix=run_id+'-')).resolve();os.chmod(root,0o700)
        (root/'ISOLATED-RUN.json').write_text(json.dumps(dict(policy=POLICY,run_id=run_id,suite=args.suite)))
        phase='source-copy';context=root/'source';context.mkdir(mode=0o700)
        selected={'client':['package.json','block-identity.js','findings-definition.js','findings-observation.js','findings-adapter.js','findings-block.js','findings-gateway.js','findings-retention.js','protected-findings-gateway.js','recovery-witness.js','recovery-witness-https.js','recovery-witness-service.js','recovery-witness-client-config.js','witnessed-retention.js','findings-backend-worker.js','witnessed-findings-gateway.js'],
            'findings-chaincode':['package.json','index.js','lib/findings.js','test/commitment-vector.json'],
            'integration':['Dockerfile','package.json','package-lock.json','sdk-fixture.js','sdk.test.js','review.test.js','material.js','findings-peer-check.js','findings-dual-peer-check.js','Dockerfile.dual','recovery-witness-fixture.js','findings-witnessed-peer-check.js','recovery-witness-https-child.js','recovery-witness-https-fixture.js','https-witness-fixture.test.js','findings-https-witnessed-peer-check.js','backend-service-fixture.py','backend-service-check.js','findings-backend-peer-check.js','Dockerfile.backend']}
        for directory,names in selected.items():
            for name in names:
                source=repo/'blockchain/fabric'/directory/name
                if source.is_symlink() or any(p.is_symlink() for p in source.parents):raise ValueError('Source symlink refused')
                dest=context/directory/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(source.read_bytes())
        # Exact source allowlist: no private keys, .env, research CSVs or node_modules.
        public_names=['package.json','package-lock.json','compile.js','contracts/FindingsAnchor.sol','payload.js','artifact.js','network.js','public-adapter.js','protected-public-runner.js','witnessed-public-runner.js','integration/witnessed-dual-check.js','integration/https-witnessed-dual-check.js','integration/local-evm.js','integration/dual-chain-check.js']
        for name in public_names:
            source=repo/'blockchain/public/findings'/name
            if source.is_symlink() or any(p.is_symlink() for p in source.parents):raise ValueError('Public source symlink refused')
            dest=context/'public/findings'/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(source.read_bytes())
        for name in ('findings_backend_gate.py','findings_backend_service.py'):
            source=repo/'backend/app/identity'/name
            if source.is_symlink() or any(p.is_symlink() for p in source.parents):raise ValueError('Backend source symlink refused')
            target=context/'backend/app/identity'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(source.read_bytes())
        logs=root/'logs';logs.mkdir(mode=0o700)
        def run(name,command,retry=False):
            nonlocal phase
            phase=name;print('Isolated Fabric phase:',name,flush=True)
            for attempt in range(30 if retry else 1):
                with (logs/(name+'-'+str(attempt)+'.log')).open('xb') as log:
                    r=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=1800 if name=='real-peer-checks' else 600)
                if r.returncode==0:return
                if not retry or attempt==29:raise RuntimeError('External phase failed')
                time.sleep(1)
        run('build-sdk',['docker','build','--label',LABEL+'='+run_id,'-t',run_id+':sdk','-f',str(context/'integration/Dockerfile.backend'),str(context)])
        run('offline-verifier-tests',['docker','run','--rm','--label',LABEL+'='+run_id,run_id+':sdk','node','--test','/work/fabric/integration/review.test.js'])
        run('https-witness-fixture-tests',['docker','run','--rm','--label',LABEL+'='+run_id,run_id+':sdk','node','--test','/work/fabric/integration/https-witness-fixture.test.js'])
        configs(root);cc=package_cc();(root/'findings.tgz').write_bytes(cc);ccid='findings_fixture:'+hashlib.sha256(cc).hexdigest()
        compose=plan(root,run_id,ccid);compose['services']['runner']['command']=['node','/work/fabric/integration/findings-backend-peer-check.js'];file=root/'compose.json';file.write_text(json.dumps(compose));base=['docker','compose','-p',run_id,'-f',str(file)]
        # No fixed container name, host port, existing network, ledger volume or
        # Docker socket is referenced. Services live on this project's network.
        tool=lambda command:base+['run','--rm','--no-deps','tools',*command]
        run('crypto',tool(['cryptogen','generate','--config=/work/run/crypto.yaml','--output=/work/run/crypto']))
        run('fixture-identities',base+['run','--rm','--no-deps','-e','PPI_TEST_ROOT=/work/run','runner','node','/work/fabric/integration/material.js'])
        roots = [
            root/'crypto'/'peerOrganizations'/f'org{i}.example.com'/
            'peers'/f'peer0.org{i}.example.com'/'tls'/'ca.crt'
            for i in (1, 2)
        ]
        bundle = root/'tls-client'/'peer-client-roots.pem'
        with bundle.open('xb') as out:
            for certificate in roots:
                out.write(certificate.read_bytes().rstrip(b'\n') + b'\n')
        os.chmod(bundle, 0o600)

        run('genesis',tool(['configtxgen','-configPath','/work/run','-profile','FindingsFixture','-channelID','personnel','-outputBlock','/work/run/genesis.block']))
        os.chmod(root/'genesis.block', 0o600)
        started=True;run('start-peers',base+['up','-d','orderer','peer1','peer2','findings'])
        order='/work/run/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/tls/'
        run('orderer-join',tool(['osnadmin','channel','join','--channelID','personnel','--config-block','/work/run/genesis.block','-o','orderer.example.com:7053',
            '--ca-file',order+'ca.crt','--client-cert',order+'server.crt','--client-key',order+'server.key']),True)
        def peer(i,command):
            e=[x for k,v in peer_env(i).items() for x in ('-e',k+'='+v)]
            return base+['run','--rm','--no-deps',*e,'tools','peer',*command]
        order_flags=['-o','orderer.example.com:7050','--ordererTLSHostnameOverride','orderer.example.com','--tls','--cafile',order+'ca.crt']
        policy="AND('Org1MSP.peer','Org2MSP.peer')"
        common=['--channelID','personnel','--name','findings-anchor-v1','--version','1.0','--sequence','1','--signature-policy',policy]
        for i in (1,2):
            run('peer'+str(i)+'-join',peer(i,['channel','join','-b','/work/run/genesis.block']),True)
            run('peer'+str(i)+'-install',peer(i,['lifecycle','chaincode','install','/work/run/findings.tgz']))
            run('peer'+str(i)+'-approve',peer(i,['lifecycle','chaincode','approveformyorg',*common,'--package-id',ccid,*order_flags]))
        run('commit-definition',peer(1,['lifecycle','chaincode','commit',*common,*order_flags,
            '--peerAddresses','peer0.org1.example.com:7051','--tlsRootCertFiles',peer_env(1)['CORE_PEER_TLS_ROOTCERT_FILE'],
            '--peerAddresses','peer0.org2.example.com:9051','--tlsRootCertFiles',peer_env(2)['CORE_PEER_TLS_ROOTCERT_FILE']]))
        for i in (1,2):run('peer'+str(i)+'-definition',peer(i,['lifecycle','chaincode','querycommitted','--channelID','personnel','--name','findings-anchor-v1']),True)
        run('real-peer-checks',base+['run','--rm','--no-deps','runner'])
        summary=json.loads((root/'PEER-PASSED.json').read_text())
        if summary.get('policy')!=POLICY or summary.get('checks')!=12 or summary.get('research_records_used')!=0:raise RuntimeError('Peer completion receipt differs')
        summary=json.loads((root/'HTTPS-WITNESS-PASSED.json').read_text())
        if summary.get('policy')!='PPI_ISOLATED_HTTPS_WITNESSED_FINDINGS_V1' or summary.get('checks')!=16 or summary.get('actual_witness_barrier_checks')!=2 or summary.get('https_checks')!=6 or summary.get('https_witness_transport') is not True or summary.get('https_witness_process') is not True or summary.get('witness_process_restarted') is not True or summary.get('independent_witness_deployment_verified') is not False or summary.get('witness_service_fixture') is not False or summary.get('research_records_used')!=0 or summary.get('fabric_actual_peers') is not True or summary.get('public_finality_simulated') is not True or summary.get('public_provider_independence') is not False:raise RuntimeError('Dual-chain completion receipt differs')
        backend=json.loads((root/'BACKEND-BRIDGE-PASSED.json').read_text())
        if (backend.get('policy')!='PPI_BACKEND_SERVICE_PEERS_V1' or backend.get('checks')!=11
            or len(backend.get('checks_completed',[]))!=11 or len(set(backend['checks_completed']))!=11
            or any(backend.get(k) is not True for k in ('actual_python_service','actual_node_worker','actual_fabric_sdk','actual_fabric_peers','https_witness_transport','full_source_replay_simulated'))
            or backend.get('independent_witness_deployment_verified') is not False
            or backend.get('live_research_ready') is not False or backend.get('research_records_used')!=0):
            raise RuntimeError('Backend bridge completion receipt differs')
        print('11 actual Python/Node backend bridge scenarios, 12 real Fabric peer checks, 6 HTTPS witness checks and 16 dual-chain scenarios passed. Source replay and public finality remain simulated; independent deployment is unverified.');clean=True;return 0
    except Exception as e:
        # Preserve this disposable project's diagnostics before cleanup.
        if started and root is not None and run_id is not None:
            try:
                with (root/'logs'/'service-failure.log').open('xb') as log:
                    subprocess.run(base+['logs','--no-color','--tail','100',
                        'orderer','peer1','peer2','findings'], env=env,
                        stdout=log, stderr=subprocess.STDOUT, timeout=30)
            except Exception as diagnostic_error:
                print('Service diagnostic capture stopped:',type(diagnostic_error).__name__)
        print('Isolated Fabric stopped at phase:',phase,'('+type(e).__name__+')')
        print('Existing network, credentials and research data were not selected. HTTPS witness/peer validation remains pending.');return 1
    finally:
        if root is not None and run_id is not None:
            try:
                # Inspect EVERY resource carrying the run marker before deleting
                # only those exact IDs. No prune, sample network.sh or global reset.
                ids=subprocess.check_output(['docker','ps','-aq','--filter','label='+LABEL+'='+run_id],env=env,text=True).split()
                if ids:
                    records=json.loads(subprocess.check_output(['docker','inspect',*ids],env=env,text=True))
                    if not owned(records,run_id):raise RuntimeError('Container cleanup ownership differs')
                    subprocess.run(['docker','rm','-fv',*ids],check=True,env=env,stdout=subprocess.DEVNULL)
                networks=subprocess.check_output(['docker','network','ls','-q','--filter','label='+LABEL+'='+run_id],env=env,text=True).split()
                for n in networks:
                    record=json.loads(subprocess.check_output(['docker','network','inspect',n],env=env,text=True))[0]
                    if record.get('Labels',{}).get(LABEL)!=run_id or record.get('Name')!=run_id:raise RuntimeError('Network cleanup ownership differs')
                    subprocess.run(['docker','network','rm',n],check=True,env=env,stdout=subprocess.DEVNULL)
                inspect=subprocess.run(['docker','image','inspect',run_id+':sdk'],env=env,capture_output=True,text=True)
                if inspect.returncode==0:
                    if not owned(json.loads(inspect.stdout),run_id):raise RuntimeError('Image cleanup ownership differs')
                    subprocess.run(['docker','image','rm',run_id+':sdk'],check=True,env=env,stdout=subprocess.DEVNULL)
                print('Owned disposable containers/network/image removed. Shared images preserved.')
                if clean:shutil.rmtree(root)
                else:print('Private failure logs retained at:',root)
            except Exception as e:
                print('Cleanup stopped:',type(e).__name__,'; preserve this run directory:',root)
                # Cleanup failure must never be reported as a successful suite.
                raise SystemExit(1)

if __name__=='__main__':raise SystemExit(main())
