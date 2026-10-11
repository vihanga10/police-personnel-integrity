"""Execute the shipped UI JavaScript against a disposable actual HTTPS backend.

No Docker, research DB, existing access configuration, RPC or chain is selected.
Requires frontend/research npm test dependencies, Python uvicorn and Node >=22.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
from research_workspace_https_fixture import server
from research_workspace_fixture import PASSWORD

def main():
    repo=Path(__file__).resolve().parents[2];frontend=repo/'frontend'/'research'
    node=shutil.which('node')
    if not node or not (frontend/'node_modules'/'jsdom'/'package.json').is_file():
        raise SystemExit('Stopped: run npm ci in frontend/research and ensure Node >=22 is available. Nothing provisioned.')
    with tempfile.TemporaryDirectory(prefix='ppi-ui-test-') as directory:
        root=Path(directory);root.chmod(0o700)
        with server(root) as (_,_,origin,_,cert):
            env={'PATH':os.environ.get('PATH',''),'PPI_UI_TEST_ORIGIN':origin,'PPI_UI_TEST_CA':str(cert),'PPI_UI_TEST_PASSWORD':PASSWORD}
            result=subprocess.run([node,str(frontend/'integration'/'https-workflow.js')],cwd=frontend,env=env,timeout=90)
            if result.returncode:raise SystemExit('Isolated UI acceptance failed. No research configuration was selected.')
    print('Owned HTTPS process, private test stores, test identities and TLS files removed. RPC 1 remains deferred.')

if __name__=='__main__':main()
