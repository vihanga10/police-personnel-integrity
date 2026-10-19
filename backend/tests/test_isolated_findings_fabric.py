import re
"""Guard the disposable harness plan. These checks do not start Docker."""
import io,json,tarfile
from pathlib import Path
import pytest
from scripts import run_isolated_findings_fabric as F


def test_unique_projects_have_no_host_ports_volumes_or_socket(tmp_path):
    a=F.plan(tmp_path,'ppi-findings-'+'a'*24,'fixture:'+ 'a'*64)
    b=F.plan(tmp_path,'ppi-findings-'+'b'*24,'fixture:'+ 'b'*64)
    assert a['networks']['fixture']['name']!=b['networks']['fixture']['name']
    for service in a['services'].values():
        assert 'ports' not in service and 'container_name' not in service and 'network_mode' not in service
        assert service['labels'][F.LABEL]=='ppi-findings-'+'a'*24
        assert service['volumes']==[str(tmp_path)+':/work/run']
        assert 'docker.sock' not in json.dumps(service)
    assert 'volumes' not in a
    for n in ('peer1','peer2','orderer'):assert a['services'][n]['tmpfs']==['/var/hyperledger/production']


@pytest.mark.parametrize('name',['fabric_test','ppi-findings-x','../escape','ppi-findings-'+'A'*24,'ppi-findings-'+'a'*25])
def test_arbitrary_existing_network_names_rejected(tmp_path,name):
    with pytest.raises(ValueError):F.plan(tmp_path,name,'fixture')


def test_exact_images_and_mutual_tls_are_selected(tmp_path):
    p=F.plan(tmp_path,'ppi-findings-'+'a'*24,'fixture')
    assert p['services']['peer1']['image']=='hyperledger/fabric-peer:2.5.16'
    assert p['services']['orderer']['image']=='hyperledger/fabric-orderer:2.5.16'
    for n in ('peer1','peer2','orderer','tools'):assert p['services'][n]['platform']=='linux/amd64'
    for n in ('peer1','peer2'):
        e=p['services'][n]['environment']
        assert e['CORE_PEER_TLS_ENABLED']==e['CORE_PEER_TLS_CLIENTAUTHREQUIRED']=='true'
        assert '/opt/hyperledger/ccaas_builder' in e['CORE_CHAINCODE_EXTERNALBUILDERS']
    assert p['services']['orderer']['environment']['ORDERER_GENERAL_BOOTSTRAPMETHOD']=='none'
    assert p['services']['runner']['environment']['PPI_TEST_ROOT']=='/work/run'


def test_chaincode_package_contains_only_fixture_endpoint_and_ccaas():
    data=F.package_cc()
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as t:
        assert set(t.getnames())=={'metadata.json','code.tar.gz'}
        meta=json.loads(t.extractfile('metadata.json').read())
        assert meta=={'type':'ccaas','label':'findings_fixture'}
        inner=t.extractfile('code.tar.gz').read()
    with tarfile.open(fileobj=io.BytesIO(inner),mode='r:gz') as t:
        assert t.getnames()==['connection.json']
        assert json.loads(t.extractfile('connection.json').read())=={'address':'findings:9999','dial_timeout':'10s','tls_required':False}


def test_inherited_network_and_database_configuration_not_forwarded(monkeypatch):
    for k in ('CORE_PEER_ADDRESS','CORE_PEER_MSPCONFIGPATH','DATABASE_URL','DOCKER_HOST','PPI_TEST_ROOT','NODE_PATH','FABRIC_CA_CLIENT_HOME','COMPOSE_FILE'):
        monkeypatch.setenv(k,'forbidden-existing-config')
    e=F.captured_env()
    assert not any(v=='forbidden-existing-config' for v in e.values())


def test_cleanup_accepts_only_exact_owned_resources():
    name='ppi-findings-'+'a'*24
    assert F.owned([{'Config':{'Labels':{F.LABEL:name}}}],name)
    assert not F.owned([{'Config':{'Labels':{F.LABEL:'other'}}}],name)
    assert not F.owned([{'Config':{'Labels':{}}}],name)
    assert not F.owned([{}],name)


def test_private_configs_are_complete_fixture_only(tmp_path):
    F.configs(tmp_path)
    text=(tmp_path/'configtx.yaml').read_text()
    assert 'FindingsFixture:' in text and 'EtcdRaft:' in text and 'LifecycleEndorsement:' in text
    assert '/work/run/crypto/' in text and 'officer-evidence' not in text
    assert 'EnableNodeOUs: true' in (tmp_path/'crypto.yaml').read_text()


def test_cli_peer_identity_is_temporary_admin_and_tls_client():
    for i in (1,2):
        e=F.peer_env(i)
        assert e['CORE_PEER_MSPCONFIGPATH'].startswith('/work/run/crypto/')
        assert e['CORE_PEER_LOCALMSPID']==f'Org{i}MSP'
        assert e['CORE_PEER_TLS_CLIENTAUTHREQUIRED']=='true'
        assert e['CORE_PEER_TLS_CLIENTKEY_FILE']=='/work/run/tls-client/key.pem'


def test_build_context_contains_all_relative_module_dependencies():
    """Prevent a packaged container reaching peers with missing local modules."""
    import ast
    tree = ast.parse(Path(F.__file__).read_text())
    selected = next(ast.literal_eval(n.value) for n in ast.walk(tree)
                    if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == 'selected' for t in n.targets))
    base = Path(F.__file__).resolve().parents[2] / 'blockchain' / 'fabric'
    included = {base / directory / name for directory, names in selected.items() for name in names}
    for source in included:
        assert source.is_file(), f'Missing packaged source: {source.name}'
        if source.suffix != '.js':
            continue
        for relative in re.findall(r"require\(['\"]([.][^'\"]+)['\"]\)", source.read_text()):
            target = (source.parent / relative).resolve()
            candidates = [target, Path(str(target) + '.js'), Path(str(target) + '.json'), target / 'index.js']
            assert any(c in included for c in candidates), f'Unpackaged dependency {relative} from {source.name}'


def test_peer_ca_bundle_has_one_explicit_path(tmp_path):
    p = F.plan(tmp_path, 'ppi-findings-' + 'a'*24, 'fixture:hash')
    for number in (1, 2):
        e = p['services']['peer'+str(number)]['environment']
        assert e['CORE_PEER_TLS_CLIENTROOTCAS_FILES'] == '/work/run/tls-client/peer-client-roots.pem'
        assert e['CORE_PEER_TLS_CLIENTAUTHREQUIRED'] == 'true'
