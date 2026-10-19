"""Launch only a new disposable PostgreSQL container for recording tests.

No database URL, existing container, credential file or Docker image override.
The integration suite independently checks this run's container and cluster.
"""
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from xml.etree import ElementTree

IMAGE = 'postgres:16'
LABEL = 'org.police-personnel-integrity.recording-test'
ENV = 'PPI_ISOLATED_RECORDING_POSTGRES_CONFIG'
DATA = '/var/lib/postgresql/data'
EXPECTED_TESTS = 23
SUITES = {'recording': ('tests/test_committed_evidence_postgres.py', EXPECTED_TESTS),
    'intake-hook': ('tests/test_controlled_recording_hook_postgres.py', 12),
    'pipeline-e2e': ('tests/test_recording_pipeline_e2e_postgres.py', 10)}
FIELDS = {'run_id','container_id','container_name','image_id','database','user',
    'password','port','cluster_name'}


def require(condition,message):
    if not condition:raise ValueError(message)


def command(*args,timeout=20):
    return subprocess.run(['docker',*args],capture_output=True,text=True,timeout=timeout)


def inspect_container(identifier):
    result=command('container','inspect',identifier)
    require(result.returncode==0,'Isolated test container inspection failed.')
    records=json.loads(result.stdout)
    require(type(records) is list and len(records)==1,'Single test container required.')
    return records[0]


def verify_container(config,record):
    require(record['Id']==config['container_id'] and
        record['Name']=='/'+config['container_name'] and
        record['Config']['Labels'].get(LABEL)==config['run_id'] and
        record['Config']['Image']==IMAGE and record['Image']==config['image_id'],
        'Isolated test container identity differs.')
    require(record['State']['Running'] is True and record['HostConfig']['AutoRemove'] is True,
        'Running disposable test container required.')
    host=record['HostConfig']
    require(host['NetworkMode'] in ('default','bridge') and not host.get('Privileged') and
        not host.get('Binds') and not host.get('Tmpfs'), 'Unsafe test container configuration.')
    mounts=host.get('Mounts',[])
    require(len(mounts)==1 and mounts[0]['Type']=='tmpfs' and mounts[0]['Target']==DATA,
        'Only disposable PostgreSQL data mount allowed.')
    require(all(m['Type']=='tmpfs' and m['Destination']==DATA for m in record.get('Mounts',[])),
        'Persistent or host mount refused.')
    ports=record['NetworkSettings']['Ports']
    require(set(ports)=={'5432/tcp'} and ports['5432/tcp']==[
        {'HostIp':'127.0.0.1','HostPort':str(config['port'])}], 'Loopback test port mapping differs.')
    env=dict(value.split('=',1) for value in record['Config']['Env'] if '=' in value)
    require(env.get('POSTGRES_DB')==config['database'] and env.get('POSTGRES_USER')==config['user'] and
        env.get('POSTGRES_PASSWORD')==config['password'] and
        env.get('POSTGRES_INITDB_ARGS')=='--auth-host=scram-sha-256', 'Test credentials differ.')
    expected=['postgres','-c','cluster_name='+config['cluster_name'],'-c','fsync=on']
    require(record['Config']['Cmd']==expected,'Test PostgreSQL startup identity differs.')


def load_config(path):
    path=Path(path).expanduser().absolute()
    require('..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents)),
        'Test configuration symlink or traversal refused.')
    require(path.is_file() and path.stat().st_uid==os.getuid() and
        not path.stat().st_mode&0o077 and path.parent.is_dir() and
        path.parent.stat().st_uid==os.getuid() and not path.parent.stat().st_mode&0o077,
        'Owner-only temporary test configuration required.')
    config=json.loads(path.read_text())
    require(type(config) is dict and set(config)==FIELDS,'Test configuration fields differ.')
    run=config['run_id']
    require(isinstance(run,str) and re.fullmatch('[0-9a-f]{32}',run),'Test run identity differs.')
    require(config['container_name']=='ppi-recording-test-'+run and
        config['database']=='ppi_recording_test_'+run and
        config['user']=='ppi_test_admin' and config['cluster_name']=='ppi-recording-'+run and
        type(config['port']) is int and 1<=config['port']<=65535 and
        isinstance(config['password'],str) and re.fullmatch('[0-9a-f]{64}',config['password']) and
        isinstance(config['container_id'],str) and re.fullmatch('[0-9a-f]{64}',config['container_id']) and
        isinstance(config['image_id'],str) and re.fullmatch('sha256:[0-9a-f]{64}',config['image_id']),
        'Isolated test configuration identity differs.')
    verify_container(config,inspect_container(config['container_id']))
    return config


def cleanup(name,run_id):
    """Remove only this UUID-labelled run, even after an interrupted launch."""
    result=command('container','inspect',name)
    if result.returncode:
        require('No such object' in result.stderr or 'No such container' in result.stderr,
            'Could not determine whether test container needs cleanup.')
        return
    records=json.loads(result.stdout)
    require(len(records)==1 and records[0]['Name']=='/'+name and
        records[0]['Config']['Labels'].get(LABEL)==run_id,
        'Cleanup refused a container outside this isolated run.')
    identifier=records[0]['Id']
    require(re.fullmatch('[0-9a-f]{64}',identifier),'Cleanup container identity differs.')
    removed=command('container','rm','--force',identifier)
    require(removed.returncode==0,'Isolated test container cleanup failed.')


def run_suite(suite='recording'):
    require(suite in SUITES,'Only installed, allowlisted test suites are accepted.')
    test_file,expected_tests=SUITES[suite]
    require(shutil.which('docker') is not None,'Docker Desktop must be installed and running.')
    require(command('info').returncode==0,'Docker Desktop must be running.')
    backend=Path(__file__).resolve().parents[1]
    require((backend/test_file).is_file(),
        'Installed PostgreSQL integration suite missing.')
    run=secrets.token_hex(16);name='ppi-recording-test-'+run
    config=dict(run_id=run,container_name=name,database='ppi_recording_test_'+run,
        user='ppi_test_admin',password=secrets.token_hex(32),cluster_name='ppi-recording-'+run)
    with tempfile.TemporaryDirectory(prefix='ppi-isolated-postgres-') as directory:
        # macOS temporary paths can traverse /var -> /private/var. Resolve our
        # newly created directory before handing off the strict config path.
        directory=Path(directory).resolve();directory.chmod(0o700)
        secret=directory/'container.env';secret.touch(mode=0o600,exist_ok=False)
        secret.write_text('POSTGRES_DB='+config['database']+'\nPOSTGRES_USER='+config['user']+
            '\nPOSTGRES_PASSWORD='+config['password']+'\nPOSTGRES_INITDB_ARGS=--auth-host=scram-sha-256\n')
        try:
            print('Starting isolated PostgreSQL 16: '+name,flush=True)
            result=command('run','--detach','--rm','--name',name,'--label',LABEL+'='+run,
                '--mount','type=tmpfs,target='+DATA+',tmpfs-size=268435456',
                '--publish','127.0.0.1::5432','--memory','512m','--env-file',str(secret),
                IMAGE,'postgres','-c','cluster_name='+config['cluster_name'],'-c','fsync=on',timeout=240)
            require(result.returncode==0,'Could not start isolated PostgreSQL (image pull may be required).')
            identifier=result.stdout.strip()
            require(re.fullmatch('[0-9a-f]{64}',identifier),'Docker returned an invalid test container identity.')
            config['container_id']=identifier
            record=inspect_container(identifier)
            bindings=record['NetworkSettings']['Ports'].get('5432/tcp')
            require(type(bindings) is list and len(bindings)==1 and bindings[0]['HostIp']=='127.0.0.1',
                'Isolated loopback test port required.')
            config['port']=int(bindings[0]['HostPort']);config['image_id']=record['Image']
            verify_container(config,record)
            deadline=time.monotonic()+60
            while True:
                ready=command('exec',identifier,'pg_isready','-h','127.0.0.1','-p','5432',
                    '-U',config['user'],'-d',config['database'],timeout=5)
                if ready.returncode==0:break
                require(time.monotonic()<deadline,'Isolated PostgreSQL did not become ready.')
                time.sleep(0.2)
            path=directory/'config.json';path.touch(mode=0o600,exist_ok=False)
            path.write_text(json.dumps(config,sort_keys=True))
            load_config(path)
            env=dict(os.environ);env[ENV]=str(path)
            env.pop('PYTEST_ADDOPTS',None);env.pop('PYTEST_PLUGINS',None)
            env['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'
            report=directory/'results.xml'
            print('Running isolated PostgreSQL integration tests; existing database credentials are unused.',flush=True)
            result=subprocess.run([sys.executable,'-m','pytest',test_file,
                '-q','--tb=short','-o','addopts=','--junitxml='+str(report)],cwd=backend,env=env)
            if result.returncode==0:
                suites=ElementTree.parse(report).getroot().iter('testsuite')
                totals={key:0 for key in ('tests','failures','errors','skipped')}
                for suite in suites:
                    for key in totals:totals[key]+=int(suite.attrib.get(key,0))
                require(totals==dict(tests=expected_tests,failures=0,errors=0,skipped=0),
                    'Integration suite did not execute every expected PostgreSQL test.')
                print(str(expected_tests)+' real PostgreSQL tests passed without skips.',flush=True)
            return result.returncode
        finally:
            cleanup(name,run)
            print('Isolated test container removed.',flush=True)


def main():
    if len(sys.argv)==1:return run_suite()
    require(len(sys.argv)==3 and sys.argv[1]=='--suite' and sys.argv[2] in SUITES,
        'Only allowlisted --suite recording, intake-hook or pipeline-e2e allowed; no database or container overrides.')
    return run_suite(sys.argv[2])


if __name__=='__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('Isolated PostgreSQL test interrupted.',file=sys.stderr);sys.exit(130)
    except (ValueError,KeyError,OSError,subprocess.SubprocessError,ElementTree.ParseError):
        print('Isolated PostgreSQL test stopped. Check Docker availability and test output; '
            'no existing database configuration was selected.',file=sys.stderr)
        sys.exit(1)
