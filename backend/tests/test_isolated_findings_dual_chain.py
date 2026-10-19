"""Packaging and isolation checks only; the Docker suite must run separately."""
import ast
import inspect
import json
import re
from pathlib import Path
from scripts import run_isolated_findings_dual_chain as D
from scripts import run_isolated_findings_fabric as F


def test_existing_isolation_and_cleanup_helpers_are_preserved(tmp_path):
    for name in ('captured_env','package_cc','configs','plan','peer_env','owned'):
        assert inspect.getsource(getattr(D,name)) == inspect.getsource(getattr(F,name)), name
    plan=D.plan(tmp_path,'ppi-findings-'+'a'*24,'fixture')
    for service in plan['services'].values():
        assert 'ports' not in service and 'network_mode' not in service and 'container_name' not in service
        assert service['volumes']==[str(tmp_path)+':/work/run']
    assert 'docker.sock' not in json.dumps(plan)


def packaged():
    tree=ast.parse(Path(D.__file__).read_text())
    def value(name):
        return next(ast.literal_eval(n.value) for n in ast.walk(tree) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets))
    repo=Path(D.__file__).resolve().parents[2]
    files={repo/'blockchain/fabric'/directory/name for directory,names in value('selected').items() for name in names}
    files.update(repo/'blockchain/public/findings'/name for name in value('public_names'))
    return files


def test_every_relative_dependency_is_in_the_disposable_context():
    files=packaged()
    for source in files:
        assert source.is_file(), source
        if source.suffix=='.js':
            for name in re.findall(r"require\(['\"]([.][^'\"]+)['\"]\)",source.read_text()):
                target=(source.parent/name).resolve()
                assert target in files or Path(str(target)+'.js') in files or Path(str(target)+'.json') in files or target/'index.js' in files, (source,name)
    assert not any(p.suffix in ('.pem','.csv') or '.env' in p.name or 'node_modules' in p.parts for p in files)


def test_compiler_contract_source_is_packaged_even_without_require():
    files=packaged();repo=Path(D.__file__).resolve().parents[2]
    assert repo/'blockchain/public/findings/contracts/FindingsAnchor.sol' in files
    assert repo/'blockchain/public/findings/package-lock.json' in files
    assert repo/'blockchain/fabric/integration/package-lock.json' in files


def test_container_installs_each_pinned_lock_and_keeps_relative_paths():
    repo=Path(D.__file__).resolve().parents[2]
    source=(repo/'blockchain/fabric/integration/Dockerfile.dual').read_text()
    assert source.count('npm ci --ignore-scripts --no-audit --no-fund')==2
    assert '/work/public/findings/' in source and '/work/fabric/client/' in source
    assert 'node:24-bookworm-slim' in source and 'docker.sock' not in source


def test_completion_requires_real_fabric_and_explicitly_simulated_public_finality():
    source=Path(D.__file__).read_text()
    assert "summary.get('checks')!=15" in source
    assert "summary.get('fabric_actual_peers') is not True" in source
    assert "summary.get('public_finality_simulated') is not True" in source
    assert "summary.get('public_provider_independence') is not False" in source
    assert "choices=('dual-chain',)" in source
    assert 'findings-dual-peer-check.js' in source
