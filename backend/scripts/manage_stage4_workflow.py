#!/usr/bin/env python3
"""Private operator CLI. Stop the web server before administrative operations."""
import argparse
from datetime import date
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.access import stage4_workflow as S
from app.access.policy import require, uid

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('prepare','renew-requests','correction','review','prepare-anchor','status'))
    p.add_argument('--repository',type=Path,required=True)
    p.add_argument('--state-root',type=Path,required=True)
    p.add_argument('--app-root',type=Path)
    p.add_argument('--connection-root',type=Path)
    p.add_argument('--audit-gate-attempt',type=Path)
    p.add_argument('--operation')
    p.add_argument('--officer')
    p.add_argument('--effective-on',type=date.fromisoformat)
    p.add_argument('--known-at')
    p.add_argument('--intent-file',type=Path)
    p.add_argument('--authority-sha256')
    p.add_argument('--receipt-file',type=Path)
    a=p.parse_args();os.umask(0o077)
    try:
        from provision_generated_connection import stopped_app
        from app.access.research_connection import revision
        revision(a.repository)
        if a.action!='status':
            app=a.app_root if a.action=='prepare' else Path(S.settings(a.state_root,a.repository)['app_root'])
            require(app,'App root required')
            stopped_app(a.repository,app)
        if a.action=='prepare':
            require(a.app_root and a.connection_root,'App and connection roots required')
            result=S.prepare(a.repository,a.state_root,a.app_root,a.connection_root)
        elif a.action=='status':result=S.readiness(a.repository,a.state_root)
        elif a.action=='renew-requests':result=S.renew_request_policy(a.repository,a.state_root)
        else:
            require(a.audit_gate_attempt,'Current connected audit attempt required')
            if a.action=='prepare-anchor':
                uid(a.officer);result=S.prepare_anchor(a.repository,a.state_root,a.audit_gate_attempt,a.officer)
            else:
                uid(a.operation)
                if a.action=='correction':
                    require(a.effective_on and a.known_at,'Changed query date and aware knowledge timestamp required')
                    result=S.correction(a.repository,a.state_root,a.audit_gate_attempt,a.operation,effective_on=a.effective_on,known_at=a.known_at)
                else:
                    require(a.intent_file and a.authority_sha256 and a.receipt_file,'Assessed review intent, authority digest and receipt required')
                    result=S.review(a.repository,a.state_root,a.audit_gate_attempt,a.operation,intent_file=a.intent_file,
                        authority_sha256=a.authority_sha256,receipt_file=a.receipt_file)
        print(json.dumps(result,indent=2));return 0
    except Exception as error:
        # Raw errors can contain private source or endpoint values.
        print(json.dumps(dict(status='STOPPED',action=a.action,error_type=type(error).__name__,
            operation_outcome='INSPECT_RETAINED_STATE_BEFORE_RETRY',chain_submitted=False)))
        return 1
if __name__=='__main__':raise SystemExit(main())
