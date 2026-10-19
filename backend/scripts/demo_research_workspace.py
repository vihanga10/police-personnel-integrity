"""Explicit temporary local UI demonstration using invented test identities only."""
from pathlib import Path
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
from research_workspace_https_fixture import server
from research_workspace_fixture import PASSWORD

def main():
    with tempfile.TemporaryDirectory(prefix='ppi-ui-demo-') as directory:
        root=Path(directory);root.chmod(0o700)
        with server(root) as (_,_,origin,_,cert):
            print('TEMPORARY TEST DEMO — invented evidence, not your research data.')
            print('Open in your browser:',origin)
            print('Test username: station.one')
            print('Test password:',PASSWORD)
            print('Search NIC: 000000001V or select NAME and search Reported Name.')
            print('The disposable localhost certificate is self-signed; it is not a production TLS configuration.')
            try:input('Keep this terminal open. Press Enter or Ctrl-C to stop and remove the demo. ')
            except (KeyboardInterrupt,EOFError):pass
    print('Disposable HTTPS service, test identities, private test stores and TLS files removed.')

if __name__=='__main__':main()
