"""Private setup helpers; source pins and destinations must be explicit."""
import hashlib
from pathlib import Path
from .core import check

PROMOTION_ROOTS=('blockchain/public/promotions','blockchain/fabric/promotions-chaincode')

def source_files(repo,roots=PROMOTION_ROOTS,clients=('promotions-',)):
    repo=Path(repo)
    paths=set()
    for relative in ['backend/app',*roots]:
        for file in (repo/relative).rglob('*'):
            if any(v in {'node_modules','test','__pycache__'} for v in file.relative_to(repo).parts):continue
            if file.is_file() and file.suffix in {'.py','.js','.sol','.json'}:paths.add(str(file.relative_to(repo)))
    for prefix in clients:paths.update(str(p.relative_to(repo)) for p in (repo/'blockchain/fabric/client').glob(prefix+'*.js'))
    paths.update(['backend/app/access/api.py','backend/app/access/research_app.py','backend/app/access/research_service.py',
        'backend/app/access/full_source_profiles.py','backend/app/access/research_store.py','backend/app/access/store.py',
        'backend/app/access/policy.py','backend/app/access/research_policy.py','backend/app/access/accountability.py',
        'blockchain/fabric/client/block-identity.js','blockchain/public/sepolia-wallet.js','blockchain/public/deployment-files.js',
        'blockchain/public/rpc-read-recovery.js','blockchain/public/rpc-read-batch.js','blockchain/public/rpc-read-pacing.js',
        'blockchain/public/live-original-check.js'])
    # Include local CommonJS dependencies recursively. Never guess the content
    # of packages installed by npm; their exact lockfiles are pinned separately.
    import re
    pending=list(paths)
    while pending:
        relative=pending.pop();file=repo/relative
        check(file.is_file() and not file.is_symlink(),'SOURCE_PIN_FILE_MISSING')
        if file.suffix!='.js':continue
        for reference in re.findall(r"require\(['\"]([^'\"]+)['\"]\)",file.read_text()):
            if not reference.startswith('.'):continue
            base=file.parent/reference
            candidate=next((p for p in [base,base.with_suffix('.js'),base.with_suffix('.json'),base/'index.js'] if p.is_file()),None)
            check(candidate is not None,'SOURCE_DEPENDENCY_MISSING')
            candidate=candidate.resolve();check(candidate.is_relative_to(repo.resolve()),'SOURCE_DEPENDENCY_OUTSIDE_REPOSITORY')
            value=str(candidate.relative_to(repo.resolve()))
            if value not in paths:paths.add(value);pending.append(value)
    return sorted(paths)

def source_pins(repo):
    return {p:hashlib.sha256((Path(repo)/p).read_bytes()).hexdigest() for p in source_files(repo)}
