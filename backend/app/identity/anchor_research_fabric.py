"""Freshly compare live evidence, authenticate its gate, then validate/submit/reconcile the original commitments."""
import argparse,hashlib,json,os,subprocess,sys,traceback
from pathlib import Path
from uuid import uuid4
from app.identity.bind_evidence_destinations import private_path
from app.identity.generate_protected_commitments import private_output
from app.identity.register_profiles import private_key_file,verify_recovery
from app.identity.destination_binding import require
from app.identity.research_anchor import authenticate_gate,authorization
from app.identity.protected_commitment import digest
from app.intake.registration_receipt import save_receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('key-file','backup-key-file','commitment-key-file','backup-commitment-key-file','bundle-attempt','binding-attempt','commitment-attempt','credential-root','output-root','network-root'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--expected-public-sha256',required=True)
    modes=parser.add_mutually_exclusive_group();modes.add_argument('--execute',action='store_true');modes.add_argument('--reconcile',action='store_true')
    args=parser.parse_args();attempt=None;os.umask(0o077)
    try:
        repo=Path(__file__).resolve().parents[3]
        require(not subprocess.check_output(['git','-C',str(repo),'status','--porcelain'],text=True).strip(),'Commit source before anchoring.')
        revision=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
        root=private_path(args.network_root,True);deployment=json.loads(private_path(root/'research-deployment/PASSED.json').read_text())
        require(deployment['status']=='PASSED' and deployment['network']['chaincode']=='officer-evidence-v1','Completed research deployment required.')
        config=private_path(root/'research-gateway-config.json')
        require(hashlib.sha256(config.read_bytes()).hexdigest()==deployment['configuration_sha256'],'Research configuration differs.')
        runtime=root/'runtime/research-client'
        for name,expected in deployment['runtime_sources'].items():
            require(hashlib.sha256(private_path(runtime/name).read_bytes()).hexdigest()==expected,'Recorded runtime source differs.')
        require(set(deployment['runtime_sources']) >= {'anchor-research.js','gateway.js','journal.js','block-identity.js','research-authorization.js'},'Research runtime modules missing.')
        for name in deployment['runtime_sources']:
            require((repo/'blockchain/fabric/client'/name).read_bytes()==(runtime/name).read_bytes(),'Commit current runtime source before anchoring.')
        public=json.loads(private_path(args.commitment_attempt/'public-commitments.json').read_text())
        require(digest(public)==args.expected_public_sha256,'Requested original publication differs.')
        mode='EXECUTE' if args.execute else 'RECONCILE' if args.reconcile else 'VALIDATE'
        output=private_output(args.output_root,repo);attempt=output/str(uuid4());attempt.mkdir(mode=0o700)
        print('Research anchoring attempt directory:',attempt,flush=True)
        save_receipt(dict(status='STARTED',mode=mode,code_revision=revision),attempt/'STARTED.json')
        command=[sys.executable,'-u','-m','app.identity.check_live_anchor_gate']
        for name in ('key-file','backup-key-file','commitment-key-file','backup-commitment-key-file','bundle-attempt','binding-attempt','commitment-attempt','credential-root'):
            command.extend(['--'+name,str(getattr(args,name.replace('-','_')))])
        command.extend(['--output-root',str(attempt/'live-gates')])
        require(subprocess.run(command,cwd=repo/'backend').returncode==0,'Fresh live evidence comparison failed.')
        gates=list((attempt/'live-gates').iterdir());require(len(gates)==1,'Expected one fresh gate attempt.')
        envelope=json.loads(private_path(gates[0]/'live-gate.encrypted.json').read_text())
        require(args.key_file.resolve()!=args.backup_key_file.resolve(),'Separate identity key copies required.')
        crypto=private_key_file(private_path(args.key_file));backup=private_key_file(private_path(args.backup_key_file));verify_recovery(crypto,backup)
        gate=authenticate_gate(envelope,crypto,backup,public,revision=revision,commitment_attempt_id=args.commitment_attempt.name,expected_sha=args.expected_public_sha256)
        secret=os.urandom(32);ticket=authorization(public,gate,deployment['network'],mode,secret)
        save_receipt(ticket,attempt/'authorization.json')
        journal_root=private_output(output/'journals',repo);journal=journal_root/public['batch_publication_id']
        if mode=='RECONCILE':private_path(journal,True)
        else:journal.mkdir(mode=0o700,exist_ok=True)
        result=attempt/'fabric-result.json'
        process=subprocess.run(['node',str(runtime/'anchor-research.js'),str(config),str(attempt/'authorization.json'),str(journal),str(result),mode],input=secret.hex()+'\n',text=True,cwd=runtime)
        require(process.returncode==0,'Fabric research workflow failed; original journals preserved.')
        summary=json.loads(private_path(result).read_text())
        require(summary['status']=='PASSED' and summary['mode']==mode and summary['officers']==6596 and summary['public_payload_sha256']==args.expected_public_sha256 and summary['network']==deployment['network'],'Fabric result binding differs.')
        save_receipt(dict(status='PASSED',mode=mode,code_revision=revision,public_payload_sha256=args.expected_public_sha256,fabric_result=summary,live_gate_attempt_id=gates[0].name),attempt/'PASSED.json')
        print('Guarded research Fabric workflow: PASSED')
        print('Exact original publication preserved; classification remains UNASSESSED. Public anchoring, audit algorithms and human disclosure remain pending.')
        return 0
    except Exception as error:
        for frame in traceback.extract_tb(error.__traceback__):
            if frame.filename.endswith(('deploy_research_fabric.py','anchor_research_fabric.py','research_anchor.py')):
                print('Code location:',Path(frame.filename).name,'line='+str(frame.lineno))
        if attempt is not None:save_receipt(dict(status='STOPPED',error_type=type(error).__name__),attempt/'STOPPED.json')
        print('Research Fabric workflow stopped:',type(error).__name__);print('All evidence, original transactions and private journals preserved; rerun the same mode with a fresh live gate.');return 1


if __name__=='__main__':raise SystemExit(main())
