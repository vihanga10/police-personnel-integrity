"""Source pins for the dataset intake runtime; destinations must be explicit."""
import hashlib
from pathlib import Path
from app.intake.promotion_pipeline import configuration as promotions

ROOTS = ('blockchain/public/intake', 'blockchain/fabric/intake-chaincode')


def source_files(repo):
    """Every backend file plus the dedicated intake chaincode, contract, worker and their local dependencies."""
    return promotions.source_files(repo, roots=ROOTS, clients=('intake-',))


def source_pins(repo):
    return {p: hashlib.sha256((Path(repo) / p).read_bytes()).hexdigest() for p in source_files(repo)}
