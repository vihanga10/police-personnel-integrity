"""Inclusion proofs for the ordered Merkle trees used by the original batch and by uploads.

Both trees hash a leaf as SHA-256(0x00 || leaf bytes) and an inner node as
SHA-256(0x01 || left || right); an odd final node pairs with itself. A proof is
only a recomputation: it shows a retained leaf belongs to a published root, not
that the underlying record is true.
"""
import hashlib


def leaf_node(data):
    return hashlib.sha256(b'\x00' + data).digest()


def inner(left, right):
    return hashlib.sha256(b'\x01' + left + right).digest()


def build(nodes):
    levels = [list(nodes)]
    while len(levels[-1]) > 1:
        level = levels[-1] + ([levels[-1][-1]] if len(levels[-1]) % 2 else [])
        levels.append([inner(level[i], level[i + 1]) for i in range(0, len(level), 2)])
    return levels


def root(nodes):
    return build(nodes)[-1][0].hex()


def proof(nodes, index):
    """[(sibling_hex, 'L'|'R'), ...] from leaf level upward; L means the sibling is on the left."""
    levels, path = build(nodes), []
    for level in levels[:-1]:
        padded = level + ([level[-1]] if len(level) % 2 else [])
        sibling = index ^ 1
        path.append((padded[sibling].hex(), 'L' if sibling < index else 'R'))
        index //= 2
    return path


def fold(node, path):
    current = node
    for sibling, side in path:
        other = bytes.fromhex(sibling)
        current = inner(other, current) if side == 'L' else inner(current, other)
    return current.hex()
