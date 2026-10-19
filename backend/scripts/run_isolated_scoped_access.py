"""Run real HTTPS login/search/revocation checks against disposable access data.

No Docker, research database, original CSV, chain, production key or user selected.
The actual ASGI application is run in an owned temporary child process and closed.
"""
from pathlib import Path
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
from scoped_access_http_fixture import checks


def main():
    with tempfile.TemporaryDirectory(prefix='ppi-scoped-access-test-') as directory:
        result=checks(Path(directory))
        if len(result)!=16 or len(set(result))!=16:raise SystemExit('Incomplete scoped access acceptance')
        print('16 actual HTTPS login/search/scope/revocation scenarios passed; disposable test identities only.')
    print('Owned ASGI process, private access DB and test TLS/key files removed.')
    print('No research data loaded or live readiness established. RPC 1 remains deferred.')

if __name__=='__main__':main()
