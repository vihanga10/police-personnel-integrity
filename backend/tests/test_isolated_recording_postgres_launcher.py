"""Launcher isolation/cleanup checks with Docker responses simulated explicitly."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import pytest
from scripts import run_isolated_recording_postgres as L


@pytest.fixture
def config():
    run='a'*32
    return dict(run_id=run,container_id='b'*64,container_name='ppi-recording-test-'+run,
        image_id='sha256:'+'c'*64,database='ppi_recording_test_'+run,user='ppi_test_admin',
        password='d'*64,port=15432,cluster_name='ppi-recording-'+run)


def record(c):
    return dict(Id=c['container_id'],Name='/'+c['container_name'],Image=c['image_id'],
        Config=dict(Image=L.IMAGE,Labels={L.LABEL:c['run_id']},
        Env=['POSTGRES_DB='+c['database'],'POSTGRES_USER='+c['user'],'POSTGRES_PASSWORD='+c['password'],
            'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256'],
        Cmd=['postgres','-c','cluster_name='+c['cluster_name'],'-c','fsync=on']),
        State={'Running':True},HostConfig=dict(AutoRemove=True,NetworkMode='default',Privileged=False,
        Binds=None,Tmpfs=None,Mounts=[{'Type':'tmpfs','Target':L.DATA}]),
        Mounts=[dict(Type='tmpfs',Destination=L.DATA)],
        NetworkSettings={'Ports':{'5432/tcp':[{'HostIp':'127.0.0.1','HostPort':str(c['port'])}]}})


def test_valid_container_identity_and_tmpfs(config):
    L.verify_container(config,record(config))


@pytest.mark.parametrize('change',['id','name','label','image','image_id','stopped','autoremove',
    'host_network','privileged','bind','extra_tmpfs','volume','other_mount','mount_count',
    'all_interfaces','port','extra_port','database','user','password','authentication','startup'])
def test_wrong_or_persistent_container_is_refused(config,change):
    r=record(config)
    if change=='id':r['Id']='e'*64
    if change=='name':r['Name']='/research'
    if change=='label':r['Config']['Labels'][L.LABEL]='e'*32
    if change=='image':r['Config']['Image']='postgres:17'
    if change=='image_id':r['Image']='sha256:'+'e'*64
    if change=='stopped':r['State']['Running']=False
    if change=='autoremove':r['HostConfig']['AutoRemove']=False
    if change=='host_network':r['HostConfig']['NetworkMode']='host'
    if change=='privileged':r['HostConfig']['Privileged']=True
    if change=='bind':r['HostConfig']['Binds']=['/research:'+L.DATA]
    if change=='extra_tmpfs':r['HostConfig']['Tmpfs']={'/other':''}
    if change=='volume':r['Mounts'][0]['Type']='volume'
    if change=='other_mount':r['HostConfig']['Mounts'][0]['Target']='/other'
    if change=='mount_count':r['HostConfig']['Mounts'].append({'Type':'tmpfs','Target':'/other'})
    if change=='all_interfaces':r['NetworkSettings']['Ports']['5432/tcp'][0]['HostIp']='0.0.0.0'
    if change=='port':r['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']='5432'
    if change=='extra_port':r['NetworkSettings']['Ports']['80/tcp']=None
    if change in ('database','user','password'):
        index={'database':0,'user':1,'password':2}[change];r['Config']['Env'][index]='POSTGRES_'+change.upper()+'=changed'
    if change=='authentication':r['Config']['Env'][3]='POSTGRES_INITDB_ARGS=--auth-host=trust'
    if change=='startup':r['Config']['Cmd']=['postgres']
    with pytest.raises(ValueError):L.verify_container(config,r)


@pytest.fixture
def config_file(config,tmp_path,monkeypatch):
    root=tmp_path/'private';root.mkdir(mode=0o700);path=root/'config.json'
    path.write_text(json.dumps(config));path.chmod(0o600)
    monkeypatch.setattr(L,'inspect_container',lambda _:record(config))
    return path


def test_owner_only_configuration_is_loaded(config,config_file):
    assert L.load_config(config_file)==config


@pytest.mark.parametrize('change',['permissions','parent','symlink','unknown','run','container','image',
    'port','password','database','user','name','cluster','traversal'])
def test_bad_configuration_is_refused_before_container_or_database_access(config_file,monkeypatch,change):
    c=json.loads(config_file.read_text());path=config_file
    if change=='permissions':path.chmod(0o644)
    elif change=='parent':path.parent.chmod(0o755)
    elif change=='symlink':path=path.parent/'link';path.symlink_to(config_file)
    elif change=='traversal':path=path.parent/'..'/'private'/'config.json'
    else:
        field={'unknown':'unexpected','run':'run_id','container':'container_id','image':'image_id',
            'port':'port','password':'password','database':'database','user':'user','name':'container_name','cluster':'cluster_name'}[change]
        c[field]='changed';config_file.write_text(json.dumps(c))
    monkeypatch.setattr(L,'inspect_container',lambda _:pytest.fail('Docker called before config guard'))
    with pytest.raises(ValueError):L.load_config(path)


def test_cleanup_removes_only_owned_label_and_exact_id(config,monkeypatch):
    calls=[]
    def cmd(*args,**kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args,0,json.dumps([record(config)]) if args[1]=='inspect' else '', '')
    monkeypatch.setattr(L,'command',cmd)
    L.cleanup(config['container_name'],config['run_id'])
    assert calls[-1]==('container','rm','--force',config['container_id'])


def test_cleanup_refuses_another_container(config,monkeypatch):
    r=record(config);r['Config']['Labels'][L.LABEL]='wrong';calls=[]
    def cmd(*args,**kwargs):calls.append(args);return subprocess.CompletedProcess(args,0,json.dumps([r]),'')
    monkeypatch.setattr(L,'command',cmd)
    with pytest.raises(ValueError):L.cleanup(config['container_name'],config['run_id'])
    assert len(calls)==1


@pytest.mark.parametrize('missing',[True,False])
def test_cleanup_distinguishes_absence_from_daemon_failure(config,monkeypatch,missing):
    message='Error: No such object' if missing else 'Cannot connect to Docker daemon'
    monkeypatch.setattr(L,'command',lambda *a,**k:subprocess.CompletedProcess(a,1,'',message))
    if missing:L.cleanup(config['container_name'],config['run_id'])
    else:
        with pytest.raises(ValueError):L.cleanup(config['container_name'],config['run_id'])


@pytest.mark.parametrize('outcome',['success','pytest_failure','skips','missing_report','startup_failure','interrupt'])
def test_launcher_scopes_resources_and_always_cleans_up(config,monkeypatch,outcome):
    calls=[];cleaned=[];c=deepcopy(config)
    monkeypatch.setattr(L.secrets,'token_hex',lambda n:'a'*32 if n==16 else 'd'*64)
    monkeypatch.setattr(L.shutil,'which',lambda _: '/fixture/docker')
    monkeypatch.setenv('DATABASE_URL','never-used-existing-research-url')
    monkeypatch.setenv('PYTEST_ADDOPTS','--collect-only')
    def cmd(*args,**kwargs):
        calls.append(args)
        if args[0]=='run':
            assert '--env-file' in args and '127.0.0.1::5432' in args and '--rm' in args
            assert '--mount' in args and not any(x.startswith('/research') for x in args)
            secret=Path(args[args.index('--env-file')+1]);assert secret.stat().st_mode&0o777==0o600
            assert c['password'] not in repr(args)
            if outcome=='startup_failure':return subprocess.CompletedProcess(args,1,'','fixture error')
            return subprocess.CompletedProcess(args,0,c['container_id'],'')
        if args[:2]==('container','inspect'):return subprocess.CompletedProcess(args,0,json.dumps([record(c)]),'')
        return subprocess.CompletedProcess(args,0,'','')
    monkeypatch.setattr(L,'command',cmd)
    monkeypatch.setattr(L,'cleanup',lambda name,run:cleaned.append((name,run)))
    def pytest_run(args,**kwargs):
        path=Path(kwargs['env'][L.ENV]);assert L.load_config(path)==c
        assert 'PYTEST_ADDOPTS' not in kwargs['env'] and kwargs['env']['PYTEST_DISABLE_PLUGIN_AUTOLOAD']=='1'
        assert 'test_committed_evidence_postgres.py' in args[3]
        if outcome=='interrupt':raise KeyboardInterrupt()
        xml=Path(next(a.split('=',1)[1] for a in args if a.startswith('--junitxml=')))
        if outcome!='missing_report':
            xml.write_text('<testsuites><testsuite tests="23" failures="0" errors="0" skipped="'+
                ('23' if outcome=='skips' else '0')+'"/></testsuites>')
        return subprocess.CompletedProcess(args,1 if outcome=='pytest_failure' else 0)
    monkeypatch.setattr(L.subprocess,'run',pytest_run)
    if outcome in ('startup_failure','skips','missing_report'):
        with pytest.raises((ValueError,OSError)):L.run_suite()
    elif outcome=='interrupt':
        with pytest.raises(KeyboardInterrupt):L.run_suite()
    else:assert L.run_suite()==(1 if outcome=='pytest_failure' else 0)
    assert cleaned==[(c['container_name'],c['run_id'])]


def test_launcher_refuses_cli_overrides(monkeypatch):
    monkeypatch.setattr(sys,'argv',['launcher','--database-url','anything'])
    with pytest.raises(ValueError):L.main()
