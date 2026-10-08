"""Read-only Docker/Node checks: no downloads, container startup, network setup or removal."""
import json
import re
import subprocess


def version(value):
    match = re.search(r'([0-9]+)\.([0-9]+)\.([0-9]+)', value)
    if not match: raise ValueError('Version format differs.')
    return tuple(map(int, match.groups()))


def check(run=subprocess.check_output):
    node = version(run(['node', '--version'], text=True, timeout=15))
    if not node >= (20, 0, 0): raise ValueError('Node 20 or later required for local test tooling.')
    docker = json.loads(run(['docker', 'version', '--format', '{{json .}}'], text=True, timeout=20))
    if not docker.get('Server'): raise ValueError('Docker engine unavailable.')
    server = docker['Server']; server_version = version(server['Version'])
    compose = version(run(['docker', 'compose', 'version', '--short'], text=True, timeout=15))
    if compose < (2, 0, 0): raise ValueError('Docker Compose v2 or later required.')
    info = json.loads(run(['docker', 'info', '--format', '{{json .}}'], text=True, timeout=20))
    if info.get('OSType') != 'linux': raise ValueError('Linux Docker engine required.')
    # Report only capability aggregates; Docker info may contain usernames/proxy endpoints.
    return dict(status='PASSED', node_version='.'.join(map(str, node)), docker_server_version='.'.join(map(str, server_version)),
                compose_version='.'.join(map(str, compose)), docker_architecture=info.get('Architecture'),
                docker_memory_gib=round(info.get('MemTotal', 0)/(1024**3), 1))


def main():
    try:
        result = check(); print('Fabric prerequisites (read-only): PASSED'); print(json.dumps(result, sort_keys=True))
        print('Fabric binaries/images, Apple Silicon compatibility, CA identity enrollment, deployment and anchoring remain unverified.')
        print('No downloads, containers, database changes or blockchain transactions performed.')
        return 0
    except Exception as error:
        print('Fabric prerequisite check stopped:', type(error).__name__)
        return 1


if __name__ == '__main__': raise SystemExit(main())
