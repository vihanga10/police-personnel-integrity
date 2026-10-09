"""Review a completed saved reconstruction; aggregate explanations, private outputs."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
from uuid import uuid4

from app.identity.bind_evidence_destinations import load_attempt, private_path
from app.identity.evidence_bundle_v2 import open_artifact, seal_artifact
from app.identity.generate_protected_commitments import load_binding, load_keys, private_output, verify_saved
from app.identity.historical_reconstruction import POLICY as HISTORY_POLICY, require
from app.identity.historical_explanation import POLICY
from app.identity.historical_result_review import replay_saved
from app.identity.inspect_stage2_coverage import ROWS
from app.identity.protected_commitment import generate, digest, POLICY as COMMITMENT_POLICY
from app.identity.public_anchor_authorization import PUBLIC_SHA
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.review_stage2 import SQL_COUNTS, MONGO_COUNTS
from app.intake.registration_receipt import save_receipt


def saved_payloads(directory, summary, crypto, backup):
    """Authenticate every expected chunk; plaintext PASSED is only a routing hint."""
    require(not (directory/'STOPPED.json').exists(), 'Incomplete saved reconstruction refused.')
    count = summary['encrypted_artifacts']
    require(type(count) is int and 1<=count<=66, 'Saved artifact count differs.')
    expected = ['history-%03d.encrypted.json'%i for i in range(count)]
    require(sorted(p.name for p in directory.glob('history-*.encrypted.json'))==expected,
        'Unexpected or missing saved chunks.')
    payloads = []
    for i,name in enumerate(expected):
        envelope = json.loads(private_path(directory/name).read_text())
        binding = dict(artifact='REPORTED_HISTORY',policy=HISTORY_POLICY,context=summary['context'],
            public_payload_sha256=PUBLIC_SHA,on=summary['on'],selection_mode=summary['selection_mode'],chunk=i)
        payload = open_artifact(crypto,envelope,binding)
        require(open_artifact(backup,envelope,binding)==payload, 'Saved result backup recovery differs.')
        payloads.append(payload)
    return payloads


def aggregate_explanations(explanations):
    """No officer identifier, raw value, type label or source row reference leaves this boundary."""
    statuses, reasons, issues, sources, modes, groups, numbers = (Counter() for _ in range(7))
    for officer in explanations:
        for e in officer['dimensions']:
            d=e['dimension'];statuses[d+':'+e['status']]+=1
            reasons.update(d+':'+r['code'] for r in e['reasons'])
            for counter,key in ((issues,'review_issue_counts'),(sources,'source_claim_counts'),
                (modes,'claim_mode_counts'),(groups,'group_counts')):
                counter.update({d+':'+k:v for k,v in e[key].items()})
            observations=e['police_number_observations']
            if observations:
                numbers.update({k:v for k,v in observations.items() if type(v) is int})
    return dict(status_counts=dict(sorted(statuses.items())),reason_counts=dict(sorted(reasons.items())),
        review_issue_counts=dict(sorted(issues.items())),source_claim_counts=dict(sorted(sources.items())),
        claim_mode_counts=dict(sorted(modes.items())),claim_group_counts=dict(sorted(groups.items())),
        police_number_observation_totals=dict(sorted(numbers.items())))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('key-file','backup-key-file','commitment-key-file','backup-commitment-key-file',
        'bundle-attempt','binding-attempt','commitment-attempt','reconstruction-attempt','output-root'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args(argv);attempt=None
    os.umask(0o077)
    try:
        repo=Path(__file__).resolve().parents[3]
        require(not subprocess.check_output(['git','-C',str(repo),'status','--porcelain'],text=True).strip(),
            'Commit reviewed source first.')
        revision=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
        paths=[private_path(p) for p in (args.key_file,args.backup_key_file)]
        require(not os.path.samefile(*paths), 'Separate recovery key copies required.')
        crypto,backup=[private_key_file(p) for p in paths];verify_recovery(crypto,backup)
        keys=load_keys(args.commitment_key_file,args.backup_commitment_key_file,repo)
        keys.assert_separate(crypto);keys.assert_separate(backup)
        public=json.loads(private_path(args.commitment_attempt/'public-commitments.json').read_text())
        require(digest(public)==PUBLIC_SHA, 'Exact original publication required.')
        manifest,catalog=load_attempt(args.bundle_attempt,crypto,backup)
        bindings,binding_sha=load_binding(args.binding_attempt,manifest,args.bundle_attempt,crypto,backup)
        envelope=json.loads(private_path(args.commitment_attempt/'commitments.encrypted.json').read_text())
        saved=open_artifact(crypto,envelope,envelope['binding'])
        require(open_artifact(backup,envelope,envelope['binding'])==saved, 'Commitment recovery differs.')
        original_revision=saved['context']['generator_revision']
        counts=dict(SQL_COUNTS,**{'staging.intake_batch':1,'staging.intake_file':len(ROWS),'staging.raw_record':sum(ROWS.values())})
        regenerated,private=generate(manifest,catalog,bindings,keys,generator_revision=original_revision,
            sql_counts=counts,mongo_counts=MONGO_COUNTS)
        require(regenerated==public and digest(regenerated)==PUBLIC_SHA, 'Original anchored snapshot differs.')
        private.update(bundle_attempt_id=args.bundle_attempt.name,binding_attempt_id=args.binding_attempt.name,
            binding_artifact_sha256=binding_sha)
        commitment_summary=dict(policy=COMMITMENT_POLICY,status='PASSED',officers=6596,source_rows=167865,
            sql_records=794200,mongo_documents=154673,code_revision=original_revision,public_payload_sha256=PUBLIC_SHA)
        verify_saved(args.commitment_attempt,crypto,backup,public,private,envelope['binding'],commitment_summary)
        directory=private_path(args.reconstruction_attempt,True)
        summary=json.loads(private_path(directory/'PASSED.json').read_text())
        payloads=saved_payloads(directory,summary,crypto,backup)
        context=dict(bundle_attempt_id=args.bundle_attempt.name,binding_attempt_id=args.binding_attempt.name,
            commitment_attempt_id=args.commitment_attempt.name,binding_artifact_sha256=binding_sha)
        explanations=replay_saved(summary,payloads,manifest,catalog,bindings,evidence_context=context,public_sha=PUBLIC_SHA)
        aggregate=aggregate_explanations(explanations)
        attempt=private_output(args.output_root,repo)/str(uuid4());attempt.mkdir(mode=0o700)
        print('Saved explanation review attempt directory:',attempt,flush=True)
        # Detailed per-officer explanation artifacts remain encrypted and recoverable.
        for chunk,offset in enumerate(range(0,len(explanations),100)):
            binding=dict(artifact='SAVED_HISTORY_EXPLANATIONS',policy=POLICY,review_revision=revision,
                reconstruction_attempt_id=directory.name,reconstruction_context=summary['context'],
                public_payload_sha256=PUBLIC_SHA,on=summary['on'],chunk=chunk)
            value=dict(policy=POLICY,results=explanations[offset:offset+100],
                source_result='COMPLETED_SAVED_RECONSTRUCTION',on=summary['on'])
            save_receipt(seal_artifact(crypto,backup,value,binding),attempt/('explanations-%03d.encrypted.json'%chunk))
        report=dict(policy=POLICY,status='PASSED',review_revision=revision,reconstruction_attempt_id=directory.name,
            reconstruction_revision=summary['code_revision'],on=summary['on'],officers=len(explanations),
            mode='SAVED_RESULT_REPLAY',new_audit_executed=False,live_readiness_claim=False,
            accepted_state_claim=False,classification='UNASSESSED',public_payload_sha256=PUBLIC_SHA,**aggregate)
        save_receipt(report,attempt/'PASSED.json')
        print('Protected saved reconstruction explanation review: PASSED')
        print(json.dumps(report,sort_keys=True))
        print('Completed saved-result replay only. No fresh audit permit, new query, live database/RPC access, personnel-value output or blockchain writes.')
        return 0
    except Exception as error:
        if attempt is not None:
            save_receipt(dict(policy=POLICY,status='STOPPED',error_type=type(error).__name__,completed=False),attempt/'STOPPED.json')
        print('Saved explanation review stopped:',type(error).__name__)
        print('No completed review issued. Original encrypted results and evidence preserved.')
        return 1


if __name__=='__main__':
    raise SystemExit(main())
