"""Explicit signed IGP/HQ log readers and optional private Fabric worker setup."""
import argparse,base64,hashlib,json,os,sys,time
from pathlib import Path
sys.path[:0]=[str(Path(__file__).resolve().parents[1]),str(Path(__file__).resolve().parent)]
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.access.policy import require,encoded,account
from app.access.store import private
from app.access.api import configured_store
from app.access.accountability import configured,POLICY,PERSISTENT_READER_POLICY
from app.access.accountability_anchor import POLICY as ANCHOR
from provision_accountability import write,stored,administration

def prepare(repo,root,execute=False,gateway=None,sha=None,anchor_root=None):
    repo=repo.resolve();root=private(root,directory=True,repo=repo)
    cfg=json.loads(private(root/'workspace-config.json',repo=repo).read_bytes())
    access,_=configured_store(cfg['access_config'])
    require(access.repo==repo,'Repository differs')
    signer=Ed25519PrivateKey.from_private_bytes(private(root/'keys/research-access-signer.key',repo=repo).read_bytes())
    kid='research-operator-access';require(signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)==access.keys[kid])
    logs=configured(cfg['accountability_config'],access=access,workspace_key=cfg['key_file'],workspace_root=cfg['state_directory'])
    config_path=private(cfg['accountability_config'],repo=repo);lc=json.loads(config_path.read_bytes())
    now=int(access.clock());grants=[]
    for login,role in [('research.igp','IGP'),('research.hq','HQ_ADMIN')]:
        user=stored(access,login)
        require(user['active'] and user['role']==role and user['scope_type']=='ALL','Expected national reader differs')
        # Do not renew account authorizations or change versions/roles to issue log access.
        user_env={'key_id':kid,'payload':user,'signature':base64.b64encode(signer.sign(encoded(user))).decode()}
        account(user_env,access.keys,now=now)
        payload={'policy':PERSISTENT_READER_POLICY if user['expires_at'] is None else POLICY,'kind':'READ_ACCESS_LOGS','user_id':user['user_id'],'account_version':user['version'],
          'issued_at':now-1,'expires_at':None if user['expires_at'] is None else min(user['expires_at'],now+86398),'review_reference':'EXPLICIT_IGP_HQ_ACCOUNTABILITY_V2'}
        grants.append((root/(login.replace('.','-')+'-log-reader.json'),{'key_id':kid,'payload':payload,'signature':base64.b64encode(signer.sign(encoded(payload))).decode()}))
    if gateway is not None:
        require(sha and anchor_root,'Gateway hash and separate anchor root required')
        raw=private(gateway,repo=repo).read_bytes();require(hashlib.sha256(raw).hexdigest()==sha,'Gateway digest differs')
        value=json.loads(raw);require(value['destination']['chaincode']=='accountability-anchor-v1' and value['destination']['organizations']==['Org1MSP','Org2MSP'],'Dedicated accountability gateway required')
        passed=json.loads(private(gateway.parent/'PASSED.json',repo=repo).read_bytes())
        require(passed['configuration_sha256']==sha and passed['writer_attribute_verified'] and passed['fresh_read_only_gateway_checked'],'Verified gateway setup required')
    if not execute:return {'status':'ACCOUNTABILITY_UPGRADE_PREVIEW_PASSED','readers':['research.igp','research.hq'],'worker_to_enable':gateway is not None,'files_changed':False}
    # Stopped app prevents simultaneous private-configuration renewal and startup.
    import socket
    with socket.socket() as s:require(s.connect_ex(('127.0.0.1',8443))!=0,'Stop the application before private setup')
    for path,grant in grants:
        write(path,grant,new=not path.exists())
        administration(logs,'LOG_READER_GRANT','ALLOWED',grant['payload']['user_id'],'EXPLICIT_IGP_HQ_LOG_INSPECTION')
    lc['reader_grants']=list(dict.fromkeys([*lc['reader_grants'],*[str(p) for p,_ in grants]]))
    if gateway is not None:
        anchor_root=anchor_root.expanduser().absolute()
        private(anchor_root.parent,directory=True,repo=repo)
        if not anchor_root.exists():anchor_root.mkdir(mode=0o700)
        private(anchor_root,directory=True,repo=repo)
        keyfile=anchor_root/'anchor.key'
        if not keyfile.exists():
            key=os.urandom(32);write(keyfile,key);write(anchor_root/'anchor-backup.key',key)
        require(private(keyfile,repo=repo).read_bytes()==private(anchor_root/'anchor-backup.key',repo=repo).read_bytes(),'Anchor key backup differs')
        pins={}
        for f in [*(repo/'blockchain/fabric/client').glob('accountability-*.js'),repo/'blockchain/fabric/client/block-identity.js',
                  repo/'blockchain/fabric/accountability-chaincode/index.js',repo/'blockchain/fabric/accountability-chaincode/lib/accountability.js',repo/'blockchain/fabric/integration/package.json',repo/'blockchain/fabric/integration/package-lock.json',*[repo/'backend/app/access'/name for name in ('accountability_anchor.py','accountability.py','accountability_activity.py')]]:
            pins[str(f.relative_to(repo))]=hashlib.sha256(f.read_bytes()).hexdigest()
        ac={'policy':ANCHOR,'state_directory':str(anchor_root),'key_file':str(keyfile),'gateway_config':str(gateway),
          'gateway_sha256':sha,'source_pins':pins,'interval_seconds':60,'batch_events':100}
        path=anchor_root/'worker-config.json'
        if path.exists():require(json.loads(private(path,repo=repo).read_bytes())==ac,'Existing worker configuration differs; reviewed migration required')
        else:write(path,ac)
        lc['anchor_config']=str(path)
    write(config_path,lc,new=False)
    return {'status':'ACCOUNTABILITY_READERS_AND_CONTROLS_CONFIGURED','readers':['research.igp','research.hq'],
      'automatic_fabric_worker_configured':bool(lc.get('anchor_config')),'live_batch_verified':False,
      'accounts_passwords_totp_scopes_changed':False,'chain_submitted':False}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repository',type=Path,required=True);p.add_argument('--app-root',type=Path,required=True)
    m=p.add_mutually_exclusive_group(required=True);m.add_argument('--preview',action='store_true');m.add_argument('--execute',action='store_true')
    p.add_argument('--gateway',type=Path);p.add_argument('--gateway-sha256');p.add_argument('--anchor-root',type=Path)
    a=p.parse_args();os.umask(0o077)
    try:print(json.dumps(prepare(a.repository,a.app_root,a.execute,a.gateway,a.gateway_sha256,a.anchor_root),indent=2))
    except Exception as e:print(json.dumps({'status':'STOPPED','error_type':type(e).__name__,'reason':str(e),'live_batch_verified':False}));raise SystemExit(1)
