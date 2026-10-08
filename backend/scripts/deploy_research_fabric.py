"""Deploy a separate research namespace on the verified existing local network; never reset it."""
import argparse,hashlib,json,os,shutil,subprocess,traceback
from pathlib import Path
from app.identity.bind_evidence_destinations import private_path
from app.identity.destination_binding import require
from app.intake.registration_receipt import save_receipt

CHAINCODE='officer-evidence-v1'


def prerequisites(root,repo):
    root=private_path(root,True)
    require(not root.resolve().is_relative_to(repo.resolve()),'Network root must remain outside Git.')
    config=json.loads(private_path(root/'gateway-config.json').read_text())
    setup=json.loads(private_path(root/'SETUP_PASSED.json').read_text())
    passed=json.loads(private_path(root/'recovery-checks/PASSED.json').read_text())
    require((setup['status'],setup['fabric'],setup['ca'],setup['test_chaincode'])==('PASSED','2.5.16','1.5.17','officer-evidence-test-v1'),'Verified setup required.')
    require(passed['status']=='PASSED' and passed['test_officers']==6596 and passed['valid_transactions']==68 and passed['interruption_cases']==4 and passed['two_peer_readback'] is True and passed['research_commitments_submitted']==0,'Real test recovery completion required.')
    require(config['chaincode']=='officer-evidence-test-v1' and config['channel']=='personnel' and
        hashlib.sha256(private_path(root/'genesis.block').read_bytes()).hexdigest()==config['genesis_sha256']==passed['network']['genesis_sha256']==setup['genesis_sha256'],'Captured network identity differs.')
    require(passed['network']['genesis_identity']['policy']=='FABRIC_GENESIS_HEADER_DATA_V1','Verified content identity required.')
    for name in ('chaincode','client'):
        lock=private_path(root/'runtime'/name/'package-lock.json')
        require(hashlib.sha256(lock.read_bytes()).hexdigest()==setup['runtime_lockfiles'][name],'Original dependency lock differs.')
    require(not any((root/n).exists() for n in ('research-deployment','research-gateway-config.json','runtime/research-chaincode','runtime/research-client')),'Research deployment already started; preserve it and inspect before recovery.')
    return root,config,setup,passed


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--network-root',type=Path,required=True)
    args=parser.parse_args();os.umask(0o077);attempt=None
    try:
        repo=Path(__file__).resolve().parents[2]
        require(not subprocess.check_output(['git','-C',str(repo),'status','--porcelain'],text=True).strip(),'Commit source before deployment.')
        revision=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
        root,config,setup,passed=prerequisites(args.network_root,repo)
        samples=root/'fabric-samples';network=samples/'test-network';orgs=network/'organizations'
        source_receipt=json.loads(private_path(root/'sample-source.json').read_text())
        require(hashlib.sha256((network/'network.sh').read_bytes()).hexdigest()==source_receipt['network_script_sha256'] and
            subprocess.check_output(['git','-C',str(samples),'rev-parse','HEAD'],text=True).strip()==setup['samples_commit'],'Recorded sample deployment source differs.')
        env=dict(os.environ,PATH=str(samples/'bin')+os.pathsep+os.environ.get('PATH',''),FABRIC_CFG_PATH=str(samples/'config'),CORE_PEER_TLS_ENABLED='true')
        def peer_env(number):
            org=orgs/('peerOrganizations/org'+str(number)+'.example.com')
            return dict(env,CORE_PEER_LOCALMSPID='Org'+str(number)+'MSP',CORE_PEER_MSPCONFIGPATH=str(org/('users/Admin@org'+str(number)+'.example.com/msp')),
                CORE_PEER_ADDRESS='localhost:'+('7051' if number==1 else '9051'),CORE_PEER_TLS_ROOTCERT_FILE=str(org/('peers/peer0.org'+str(number)+'.example.com/tls/ca.crt')))
        for number in (1,2):
            defs=json.loads(subprocess.check_output(['peer','lifecycle','chaincode','querycommitted','--channelID','personnel','--output','json'],env=peer_env(number),stderr=subprocess.PIPE,text=True))
            require(not any(d['name']==CHAINCODE for d in defs.get('chaincode_definitions',[])),'Research namespace already committed; no replacement deployment.')
        attempt=root/'research-deployment';attempt.mkdir(mode=0o700)
        save_receipt(dict(status='STARTED',code_revision=revision,chaincode=CHAINCODE),attempt/'STARTED.json')
        def run(phase,command,cwd,environment=None):
            print('Research deployment phase:',phase,flush=True)
            with (attempt/(phase+'.log')).open('xb') as log:
                result=subprocess.run(command,cwd=cwd,env=environment,stdout=log,stderr=subprocess.STDOUT,timeout=1800)
            require(result.returncode==0,'Research deployment phase failed: '+phase)
        runtime_sources={};chaincode_sources={}
        for name,target_name in (('chaincode','research-chaincode'),('client','research-client')):
            target=root/'runtime'/target_name;target.mkdir(mode=0o700)
            source=repo/'blockchain/fabric'/name
            for p in source.rglob('*'):
                if p.is_file() and not p.is_symlink() and p.suffix in ('.js','.json') and 'node_modules' not in p.parts and 'test' not in p.relative_to(source).parts:
                    require(not any(q.is_symlink() for q in p.parents),'Source path traverses symlink.')
                    relative=p.relative_to(source);destination=target/relative;destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                    destination.write_bytes(p.read_bytes())
                    (runtime_sources if name=='client' else chaincode_sources)[str(relative)]=hashlib.sha256(p.read_bytes()).hexdigest()
            shutil.copyfile(root/'runtime'/name/'package-lock.json',target/'package-lock.json')
            require((target/'package.json').read_bytes()==(root/'runtime'/name/'package.json').read_bytes(),'Pinned runtime dependency declaration differs.')
            run(name+'_dependencies',['npm','ci','--ignore-scripts','--no-audit','--no-fund'],target)
        run('chaincode_deploy',['bash','./network.sh','deployCC','-c','personnel','-ccn',CHAINCODE,'-ccp',str(root/'runtime/research-chaincode'),'-ccl','javascript','-ccv','1.0','-ccs','1','-ccep',"AND('Org1MSP.peer','Org2MSP.peer')"],network)
        definitions=[]
        for number in (1,2):
            definition=json.loads(subprocess.check_output(['peer','lifecycle','chaincode','querycommitted','--channelID','personnel','--name',CHAINCODE,'--output','json'],env=peer_env(number),stderr=subprocess.PIPE,text=True))
            require(definition['version']=='1.0' and int(definition['sequence'])==1 and definition.get('validation_parameter'),'Committed definition differs.')
            save_receipt(definition,attempt/('definition-org'+str(number)+'.json'));definitions.append(definition)
        require(all(definitions[0].get(k)==definitions[1].get(k) for k in ('version','sequence','validation_parameter','endorsement_plugin','validation_plugin','init_required')),'Peer committed definitions differ.')
        research_config=dict(config,chaincode=CHAINCODE);save_receipt(research_config,root/'research-gateway-config.json')
        descriptor=dict(passed['network'],chaincode=CHAINCODE)
        summary=dict(status='PASSED',code_revision=revision,network=descriptor,runtime_sources=runtime_sources,chaincode_sources=chaincode_sources,
            configuration_sha256=hashlib.sha256((root/'research-gateway-config.json').read_bytes()).hexdigest(),definition_sha256=hashlib.sha256(json.dumps(definitions[0],sort_keys=True).encode()).hexdigest(),research_commitments_submitted=0)
        save_receipt(summary,attempt/'PASSED.json')
        print('Separate research chaincode deployment: PASSED');print(json.dumps(dict(status='PASSED',channel='personnel',chaincode=CHAINCODE,sequence=1,research_commitments_submitted=0),sort_keys=True))
        print('Existing test ledger preserved. Next: fresh live gate and guarded research validation.')
        return 0
    except Exception as error:
        for frame in traceback.extract_tb(error.__traceback__):
            if frame.filename.endswith(('deploy_research_fabric.py','anchor_research_fabric.py','research_anchor.py')):
                print('Code location:',Path(frame.filename).name,'line='+str(frame.lineno))
        if attempt is not None:save_receipt(dict(status='STOPPED',error_type=type(error).__name__),attempt/'STOPPED.json')
        print('Research deployment stopped:',type(error).__name__);print('Existing network and deployment logs preserved; no reset or chaincode replacement requested.');return 1


if __name__=='__main__':raise SystemExit(main())
