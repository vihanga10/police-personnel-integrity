"""Disposable HTTPS ASGI service for API and real UI-script integration tests."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
from research_workspace_fixture import initialize
from scoped_access_http_fixture import certificate

@contextmanager
def server(root,prepared=None):
    root=Path(root).resolve();store,key,configfile=prepared if prepared else initialize(root)
    accessconfig=Path(json.loads(configfile.read_text())['access_config'])
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    origin='https://127.0.0.1:'+str(port);access=json.loads(accessconfig.read_text());access['origin']=origin;accessconfig.write_text(json.dumps(access))
    certfile,keyfile=certificate(root);backend=Path(__file__).resolve().parents[1]
    env={'PATH':os.environ.get('PATH',''),'PYTHONPATH':str(backend),'PPI_RESEARCH_CONFIG':str(configfile),'PYTHONUNBUFFERED':'1'}
    log=root/'web-test.log';log.touch(mode=0o600);process=None
    try:
        with log.open('wb') as out:
            process=subprocess.Popen([sys.executable,'-m','uvicorn','app.access.research_app:application','--factory',
                '--host','127.0.0.1','--port',str(port),'--workers','1','--no-proxy-headers','--no-access-log',
                '--ssl-certfile',str(certfile),'--ssl-keyfile',str(keyfile),'--log-level','warning'],
                cwd=backend,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT)
        context=ssl.create_default_context(cafile=str(certfile));context.minimum_version=ssl.TLSVersion.TLSv1_3
        until=time.monotonic()+15
        while True:
            if process.poll() is not None:raise RuntimeError('Disposable research HTTPS server failed; inspect private fixture log')
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=1) as conn:
                    with context.wrap_socket(conn,server_hostname='127.0.0.1'):break
            except (OSError,ssl.SSLError):
                if time.monotonic()>=until:raise RuntimeError('Disposable HTTPS readiness timed out')
                time.sleep(.05)
        yield store,key,origin,context,certfile
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
