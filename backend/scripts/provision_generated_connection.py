"""Prepare or connect the user's anchored generated research records, operator only."""
import argparse
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from urllib.parse import urlsplit
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.access import generated_connection as G, research_connection as C
from app.access import research_connection_runtime as R
from app.access.policy import require


def defaults(repo):
    home = Path.home(); keys = home / 'ResearchKeys/police-personnel-integrity'
    evidence = home / 'ResearchEvidence/police-personnel-integrity'
    return dict(key_file=str(repo/'backend/.secrets/identity-keys.json'),
        backup_key_file=str(keys/'identity-keys-initial.json'),
        commitment_key_file=str(keys/'commitment-v1/keys.json'),
        backup_commitment_key_file=str(keys/'commitment-v1-backup/keys.json'),
        bundle_attempt=str(evidence/'evidence-bundle-attempts/f2f04bd3-673e-4dad-8f7a-7f4b60290025'),
        binding_attempt=str(evidence/'destination-binding-attempts/621e6c66-7009-4ac0-a793-a69da6c67762'),
        commitment_attempt=str(evidence/'protected-commitment-attempts/ea037905-647d-419e-b250-f688fd246a50'))


def stopped_app(repo, app_root):
    config = R.read_json(app_root/'access-config.json', repo)
    url = urlsplit(config['origin'])
    require(url.hostname in ('127.0.0.1','localhost') and url.scheme=='https', 'Local HTTPS application required')
    with socket.socket() as sock:
        sock.settimeout(1)
        require(sock.connect_ex(('127.0.0.1',url.port or 443))!=0, 'Stop the application server before connecting')


def audit_and_connect(repo, root, app_root, profile, officers=None, review_policy=None, *, all_source_profiles=False, all_history=False):
    require(not (all_source_profiles and all_history))
    plan = G.validate_plan(repo, root, app_root)
    from app.identity.audit_read_rpc_profile import load, ENV_NAMES
    require(not any(os.environ.get(name) for name in ENV_NAMES), 'Inherited profile environment refused')
    keys = Path.home()/'ResearchKeys/police-personnel-integrity'
    evidence = Path.home()/'ResearchEvidence/police-personnel-integrity'
    profile = R.private(profile, repo=repo)
    profile_sha = hashlib.sha256(profile.read_bytes()).hexdigest()
    load(profile, profile_sha, keys/'sepolia-v1', repo)
    command = [sys.executable,'-u','-m','app.identity.check_audit_gate_read_rpc']
    values = {**plan['source'], 'credential_root':str(keys), 'network_root':str(keys/'fabric-local-v1'),
        'wallet_root':str(keys/'sepolia-v1'),'backup_wallet_root':str(keys/'sepolia-v1-backup'),
        'fabric_output_root':str(evidence/'research-fabric-anchor-attempts'),
        'output_root':str(evidence/'audit-gate-attempts'),'publication_fee_budget_eth':'2.30',
        'read_profile':str(profile),'expected_read_profile_sha256':profile_sha}
    for name,value in values.items(): command += ['--'+name.replace('_','-'),value]
    print('Full read-only audit starts; dataset connection runs only after READY.',flush=True)
    attempt = None
    with subprocess.Popen(command,cwd=repo/'backend',stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True) as process:
        try:
            for line in process.stdout:
                print(line,end='',flush=True)
                if line.startswith('Audit gate attempt directory: '):
                    require(attempt is None, 'Duplicate audit result path')
                    attempt = Path(line.removeprefix('Audit gate attempt directory: ').strip())
            result = process.wait()
        except BaseException:
            process.terminate(); process.wait(); raise
    require(result==0 and attempt is not None, 'Full audit did not succeed; no connection import attempted')
    require(attempt.parent==evidence/'audit-gate-attempts', 'Unexpected audit result directory')
    ready = R.read_json(attempt/'READY.json',repo)
    require(ready['status']=='READY' and ready['code_revision']==C.revision(repo), 'Fresh READY result differs')
    require(hashlib.sha256(profile.read_bytes()).hexdigest()==profile_sha,'Read profile changed during audit')
    if all_history:
        from app.access.all_history_connection import connect_all
        return connect_all(repo,root,app_root,attempt,progress=lambda stage:print('All histories: '+stage,flush=True))
    if all_source_profiles:
        from app.access.full_source_connection import connect_all
        return connect_all(repo,root,app_root,attempt,progress=lambda stage:print('Full profiles: '+stage,flush=True))
    return G.connect(repo,root,app_root,attempt,selected_officers=officers,review_policy=review_policy,progress=lambda stage: print('Stage 3: '+stage,flush=True))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('prepare','connect','audit-connect','audit-connect-all','audit-connect-history','connect-history'))
    parser.add_argument('--repository',type=Path,required=True)
    parser.add_argument('--state-root',type=Path,required=True)
    parser.add_argument('--app-root',type=Path,required=True)
    parser.add_argument('--detail-limit',type=int,default=2)
    parser.add_argument('--effective-on',type=date.fromisoformat)
    parser.add_argument('--source-config',type=Path)
    parser.add_argument('--audit-gate-attempt',type=Path)
    parser.add_argument('--read-profile',type=Path)
    parser.add_argument('--officer',action='append')
    parser.add_argument('--stage4-policy',type=Path)
    args=parser.parse_args();os.umask(0o077);stage='SOURCE_AND_ARGUMENTS'
    try:
        repo=args.repository.expanduser().resolve();root=args.state_root.expanduser().absolute();app=args.app_root.expanduser().absolute()
        require(subprocess.check_output(['git','-C',str(repo),'branch','--show-current'],text=True).strip()=='feat/identity-resolution')
        C.revision(repo)
        if args.action=='prepare':
            require(args.audit_gate_attempt is None and args.read_profile is None and args.officer is None and args.stage4_policy is None)
            source=R.read_json(args.source_config,repo) if args.source_config else defaults(repo)
            stage='PRIVATE_PREPARATION';result=G.prepare(repo,root,app,source,detail_limit=args.detail_limit,effective_on=args.effective_on)
        else:
            require(args.source_config is None and args.effective_on is None and args.detail_limit==2,'Preparation-only arguments refused')
            stopped_app(repo,app)
            if args.action in ('audit-connect','audit-connect-all','audit-connect-history'):
                require(args.read_profile is not None and args.audit_gate_attempt is None)
                require(args.action=='audit-connect' or (args.officer is None and args.stage4_policy is None),'Bulk connection does not grant reviewer authority')
                stage='FULL_AUDIT_AND_CONNECTION';result=audit_and_connect(repo,root,app,args.read_profile,args.officer,args.stage4_policy,
                    all_source_profiles=args.action=='audit-connect-all',all_history=args.action=='audit-connect-history')
            else:
                require(args.audit_gate_attempt is not None and args.read_profile is None)
                stage='VERIFIED_DATASET_CONNECTION'
                if args.action=='connect-history':
                    require(args.officer is None and args.stage4_policy is None)
                    from app.access.all_history_connection import connect_all
                    result=connect_all(repo,root,app,args.audit_gate_attempt,progress=lambda value:print('All histories: '+value,flush=True))
                else:result=G.connect(repo,root,app,args.audit_gate_attempt,selected_officers=args.officer,review_policy=args.stage4_policy,
                        progress=lambda value: print('Stage 3: '+value,flush=True))
        print(json.dumps(result,indent=2))
        if args.action!='prepare':print('Restart the existing HTTPS application and sign in again. Open Connected detail views within your scope.')
        return 0
    except Exception as error:
        print(json.dumps(dict(status='STOPPED',stage=stage,error_type=type(error).__name__,
            connection_complete=False,partial_private_state_may_exist=stage!='SOURCE_AND_ARGUMENTS',
            original_source_or_chain_modified=False)))
        print('Preserve existing private journals and import attempts. Check the Stage 3 runbook; never delete state to bypass a stop.',file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
