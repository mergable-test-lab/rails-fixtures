import base64
import hashlib
import json
import os
import pathlib
import re
import selectors
import subprocess
import sys
import tempfile
import time

ASSETS = pathlib.Path(__file__).resolve().parent
SHA = re.compile(r'[0-9a-f]{40}\Z')
SOURCE = 'script/total_cents.rb'
INPUT = b'{"items":[{"cents":1250,"quantity":2}]}'
FILES = ['controller.py', 'profile.json', 'seccomp.json', 'suite.json', 'workflow.yml', 'fixture/script/total_cents.rb', 'fixture/Gemfile', 'fixture/.gitattributes', 'fixture/.gitconfig']


class Refused(Exception):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused('Duplicate JSON key')
        result[key] = value
    return result


def read_json(value):
    return json.loads(value, object_pairs_hook=unique)


def command(argv, limit=262144, timeout=20, env=None):
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=env, close_fds=True, start_new_session=True)
    streams = selectors.DefaultSelector()
    streams.register(child.stdout, selectors.EVENT_READ, 0)
    streams.register(child.stderr, selectors.EVENT_READ, 1)
    output = [bytearray(), bytearray()]
    deadline = time.monotonic() + timeout
    try:
        while streams.get_map():
            if time.monotonic() >= deadline:
                raise Refused('Trusted command deadline exceeded')
            for key, _ in streams.select(min(0.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 16384)
                if not chunk:
                    streams.unregister(key.fileobj)
                elif len(output[0]) + len(output[1]) + len(chunk) > limit:
                    raise Refused('Trusted command output exceeded bound')
                else:
                    output[key.data].extend(chunk)
        if child.wait(timeout=max(.01, deadline - time.monotonic())) != 0:
            raise Refused('Trusted command failed')
        return bytes(output[0])
    finally:
        streams.close()
        if child.poll() is None:
            os.killpg(child.pid, 9)
        child.wait()
        child.stdout.close()
        child.stderr.close()


def stage(repository, revision, destination, token, qualification=False):
    projection = ".mergable/runtime/fixture/" + SOURCE if qualification else SOURCE
    import urllib.request
    import urllib.parse
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', repository) or not SHA.fullmatch(revision):
        raise Refused('Invalid source identity')
    deadline = time.monotonic() + 30
    remaining_bytes = 524288
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args):
            raise Refused('Source redirect refused')
    opener = urllib.request.build_opener(NoRedirect)
    def fetch(path, cap):
        nonlocal remaining_bytes
        if time.monotonic() >= deadline:
            raise Refused('Source read deadline exceeded')
        request = urllib.request.Request('https://api.github.com/repos/' + repository + '/git/' + path,
                                        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json'})
        data = bytearray()
        with opener.open(request, timeout=min(10, deadline - time.monotonic())) as response:
            while True:
                if time.monotonic() >= deadline:
                    raise Refused('Source read deadline exceeded')
                chunk = response.read(min(16384, cap + 1 - len(data)))
                if not chunk:
                    break
                if len(data) + len(chunk) > cap or len(chunk) > remaining_bytes:
                    raise Refused('Source read byte limit exceeded')
                remaining_bytes -= len(chunk)
                data.extend(chunk)
        return read_json(data)
    commit = fetch('commits/' + revision, 65536)
    if commit.get('sha') != revision or not SHA.fullmatch(commit.get('tree', {}).get('sha', '')):
        raise Refused('Source commit identity differs')
    tree_oid = commit['tree']['sha']
    tree = fetch('trees/' + tree_oid + '?recursive=1', 262144)
    if tree.get('sha') != tree_oid or tree.get('truncated') is not False or not isinstance(tree.get('tree'), list) or len(tree['tree']) > 2048:
        raise Refused('Source tree is incomplete')
    selected = None
    seen = set()
    for entry in tree['tree']:
        path = entry.get('path')
        if not isinstance(path, str) or len(path.encode()) > 512 or path in seen or path.startswith('/') or any(part in ('', '.', '..') for part in path.split('/')):
            raise Refused('Source path is unsupported')
        seen.add(path)
        if path == 'script' and (entry.get('mode') != '040000' or entry.get('type') != 'tree'):
            raise Refused('Source directory is not a raw tree')
        if path == projection:
            if entry.get('mode') not in ('100644', '100755') or entry.get('type') != 'blob' or not SHA.fullmatch(entry.get('sha', '')) or not isinstance(entry.get('size'), int) or not 0 < entry['size'] <= 65536:
                raise Refused('Source blob mode or size is unsupported')
            selected = entry
    if selected is None:
        raise Refused('Approved source projection missing')
    if qualification:
        entries = {entry['path']: entry for entry in tree['tree']}
        for name in FILES:
            if name.startswith('fixture/'):
                data = (ASSETS / name).read_bytes()
                oid = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
                installed = entries.get('.mergable/runtime/' + name, {})
                if installed.get('sha') != oid or installed.get('mode') != '100644':
                    raise Refused('Hosted setup trap fixture differs')
    blob = fetch('blobs/' + selected['sha'], 131072)
    if blob.get('sha') != selected['sha'] or blob.get('size') != selected['size'] or blob.get('encoding') != 'base64':
        raise Refused('Source blob identity differs')
    content = base64.b64decode(''.join(blob['content'].split()), validate=True)
    if len(content) != selected['size'] or hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest() != selected['sha']:
        raise Refused('Raw source bytes differ')
    destination = pathlib.Path(destination)
    destination.mkdir(mode=0o755)
    (destination / 'script').mkdir(mode=0o755)
    fd = os.open(destination / SOURCE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    with os.fdopen(fd, 'wb') as output:
        output.write(content)
    manifest = [{'path': SOURCE, 'git_mode': selected['mode'], 'oid': selected['sha'], 'sha256': digest(content), 'bytes': len(content)}]
    return {'commit_sha': revision, 'tree_oid': tree_oid, 'projection_sha256': digest(canonical(manifest)), 'files': manifest}


def runtime_contract(image):
    return digest(canonical({'assets': {name: digest((ASSETS / name).read_bytes()) for name in FILES}, 'image': image}))


class Runtime:
    def __init__(self, image, platform, deadline, hosted=True):
        if not re.fullmatch(r'ruby@sha256:[0-9a-f]{64}', image) or platform not in ('linux/amd64', 'linux/arm64'):
            raise Refused('Only a pinned prepared Ruby image is supported')
        self.image, self.platform, self.deadline = image, platform, deadline
        self.profile = read_json((ASSETS / 'profile.json').read_bytes())
        self.env = {key: os.environ[key] for key in ('PATH', 'HOME', 'DOCKER_HOST', 'DOCKER_CONTEXT') if key in os.environ}
        self.hosted = hosted
        if hosted and (platform != 'linux/amd64' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or
                       os.environ.get('RUNNER_OS') != 'Linux' or not os.environ.get('ImageVersion')):
            raise Refused('A standard GitHub hosted Linux image is required')
        info = self.docker('image', 'inspect', image)[0]
        if info['Architecture'] != platform.split('/')[1] or info['Os'] != 'linux' or image not in info['RepoDigests']:
            raise Refused('Image platform or digest mismatch')
        config = info['Config']
        if config.get('Volumes') or config.get('OnBuild'):
            raise Refused('Automatic image volumes and build hooks are unsupported')
        version = self.docker('version', '--format', '{{json .Server}}')
        engine = self.docker('info', '--format', '{{json .}}')
        components = {entry['Name']: entry['Version'] for entry in version['Components']}
        if 'runc' not in components or not any('seccomp' in option for option in engine['SecurityOptions']):
            raise Refused('Runtime enforcement unavailable')
        self.fingerprint = {'runner_image': os.environ.get('ImageOS', 'local'), 'runner_version': os.environ.get('ImageVersion', 'local'),
                            'architecture': info['Architecture'], 'kernel': engine['KernelVersion'], 'docker': version['Version'],
                            'runc': components['runc'], 'cgroup_version': engine['CgroupVersion'], 'cgroup_driver': engine['CgroupDriver'],
                            'security_options_sha256': digest(canonical(sorted(engine['SecurityOptions']))),
                            'seccomp_sha256': digest((ASSETS / 'seccomp.json').read_bytes()),
                            'profile_sha256': digest((ASSETS / 'profile.json').read_bytes()), 'image': image,
                            'contract_sha256': runtime_contract(image)}
        if any(not isinstance(value, str) or not value or len(value) > 256 for value in self.fingerprint.values()):
            raise Refused('Incomplete runtime fingerprint')

    def docker(self, *args, json_output=True):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Refused('Execution envelope exhausted')
        result = command(['docker', *args], timeout=min(20, remaining), env=self.env)
        return read_json(result) if json_output else result.decode().strip()

    def execute(self, source, stdin=INPUT, cancel_after=None):
        source = pathlib.Path(source).resolve()
        before = digest((source / SOURCE).read_bytes())
        name = 'mergable-' + os.urandom(16).hex()
        argv = ['create', '--interactive', '--pull=never', '--name', name, '--platform', self.platform,
                '--user=1000:1000', '--cap-drop=ALL', '--security-opt=no-new-privileges=true',
                '--security-opt=seccomp=' + str(ASSETS / 'seccomp.json'), '--read-only', '--network=none',
                '--cgroupns=private', '--ipc=private', '--pids-limit=32', '--memory=256m', '--memory-swap=256m',
                '--cpus=0.5', '--ulimit=nofile=256:256', '--ulimit=core=0:0', '--no-healthcheck', '--log-driver=none',
                '--workdir=/candidate', '--mount', 'type=bind,src=' + str(source) + ',dst=/candidate,readonly',
                '--tmpfs', '/scratch:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=1000,gid=1000',
                '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=1000,gid=1000',
                '--entrypoint=/usr/bin/env', self.image, '-i', 'PATH=/usr/local/bin:/usr/bin:/bin',
                'HOME=/scratch', 'TMPDIR=/tmp', 'LANG=C.UTF-8', '/usr/local/bin/ruby', '/candidate/' + SOURCE]
        container = None
        attach = None
        streams = selectors.DefaultSelector()
        output = {'stdout': bytearray(), 'stderr': bytearray()}
        stopped = None
        cleanup = False
        started = None
        state = {}
        controls = None
        try:
            container = self.docker(*argv, json_output=False)
            if not re.fullmatch(r'[0-9a-f]{64}', container):
                raise Refused('Invalid container identity')
            inspection = self.docker('inspect', container)[0]
            controls = self.inspect_controls(inspection, source)
            started = time.time()
            attach = subprocess.Popen(['docker', 'start', '--attach', '--interactive', container], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env, close_fds=True, start_new_session=True)
            attach.stdin.write(stdin)
            attach.stdin.close()
            streams.register(attach.stdout, selectors.EVENT_READ, 'stdout')
            streams.register(attach.stderr, selectors.EVENT_READ, 'stderr')
            stop_at = min(time.monotonic() + self.profile['wall_seconds'], self.deadline - 20)
            cancel_at = time.monotonic() + cancel_after if cancel_after is not None else None
            while streams.get_map():
                if cancel_at is not None and time.monotonic() >= cancel_at:
                    stopped = 'cancelled'
                    break
                if time.monotonic() >= stop_at:
                    stopped = 'wall_timeout'
                    break
                for key, _ in streams.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 16384)
                    if not chunk:
                        streams.unregister(key.fileobj)
                        continue
                    remaining = self.profile['output_bytes'] - sum(map(len, output.values()))
                    output[key.data].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        stopped = 'output_limit'
                        break
                if stopped:
                    break
            if stopped:
                if attach.poll() is None:
                    os.killpg(attach.pid, 9)
                attach.wait(timeout=5)
                self.docker('kill', container, json_output=False)
            attach.wait(timeout=5)
            state = self.docker('inspect', container)[0]['State']
            if state['Running']:
                self.docker('kill', container, json_output=False)
                state = self.docker('inspect', container)[0]['State']
                stopped = stopped or 'background_process'
        finally:
            streams.close()
            if attach:
                if attach.poll() is None:
                    os.killpg(attach.pid, 9)
                attach.wait()
                attach.stdout.close()
                attach.stderr.close()
            if container:
                command(['docker', 'rm', '--force', container], timeout=10, env=self.env)
                cleanup = not self.docker('ps', '--all', '--filter', 'id=' + container, '--format', '{{.ID}}', json_output=False)
        after = digest((source / SOURCE).read_bytes())
        retained = {role: bytes(value) for role, value in output.items()}
        process = {'started_at': started, 'completed_at': time.time(), 'exit_code': state['ExitCode'],
                   'oom_killed': state['OOMKilled'], 'stop_reason': stopped, 'runtime_error': bool(state['Error']),
                   'cleanup_complete': cleanup, 'source_unchanged': before == after, 'effective_controls_sha256': digest(canonical(controls))}
        complete = cleanup and before == after and not stopped and not state['OOMKilled'] and not state['Error'] and state['ExitCode'] == 0
        probe = 'inconclusive'
        if complete:
            try:
                parsed = read_json(retained['stdout'].decode('utf-8'))
                probe = 'observed_match' if type(parsed) is dict and parsed == {'total_cents': 2500} and type(parsed.get('total_cents')) is int else 'observed_mismatch'
            except (ValueError, Refused):
                probe = 'observed_mismatch'
        return {'process': process, 'payloads': {role: {'sha256': digest(value), 'bytes': len(value), 'truncated': stopped == 'output_limit'} for role, value in retained.items()},
                'probe': probe, 'source_sha256': before, 'controls': controls}, retained

    def inspect_controls(self, inspection, source):
        host = inspection['HostConfig']
        expected = {'Privileged': False, 'ReadonlyRootfs': True, 'NetworkMode': 'none', 'PidMode': '', 'IpcMode': 'private',
                    'CgroupnsMode': 'private', 'CapDrop': ['ALL'], 'Memory': 268435456, 'MemorySwap': 268435456,
                    'NanoCpus': 500000000, 'PidsLimit': 32, 'Devices': [], 'DeviceRequests': None}
        if any(host.get(key) != value for key, value in expected.items()):
            raise Refused('Effective container restrictions differ')
        if host['LogConfig']['Type'] != 'none' or host.get('CapAdd') or host.get('PortBindings') or host.get('ExtraHosts'):
            raise Refused('Undeclared container access')
        if not any(value.startswith('no-new-privileges') for value in host['SecurityOpt']) or not any(value.startswith('seccomp=') for value in host['SecurityOpt']):
            raise Refused('Required process restrictions missing')
        mounts = inspection['Mounts']
        binds = [mount for mount in mounts if mount['Type'] == 'bind']
        if len(binds) != 1 or binds[0]['Source'] != str(source) or binds[0]['Destination'] != '/candidate' or binds[0]['RW']:
            raise Refused('Source mount differs')
        if any(mount['Type'] not in ('bind', 'tmpfs') for mount in mounts) or set(host['Tmpfs']) != {'/scratch', '/tmp'}:
            raise Refused('Undeclared mount')
        if sorted(host['Ulimits'], key=lambda item: item['Name']) != [{'Name': 'core', 'Hard': 0, 'Soft': 0}, {'Name': 'nofile', 'Hard': 256, 'Soft': 256}]:
            raise Refused('Descriptor or core limits differ')
        expected_tmpfs = 'rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=1000,gid=1000'
        if any(value != expected_tmpfs for value in host['Tmpfs'].values()):
            raise Refused('Scratch limits differ')
        if inspection['Config']['User'] != '1000:1000' or inspection['Config']['Entrypoint'] != ['/usr/bin/env']:
            raise Refused('Candidate identity differs')
        return {**expected, 'seccomp_sha256': digest((ASSETS / 'seccomp.json').read_bytes()), 'tmpfs': host['Tmpfs'],
                'ulimits': host['Ulimits'], 'network': inspection['NetworkSettings']['Networks'], 'source_readonly': True}


class SyntheticNetwork:
    def __init__(self, runtime):
        self.runtime = runtime
        self.name = 'mergable-probe-' + os.urandom(12).hex()
        self.listener = None
        self.created = False

    def __enter__(self):
        try:
            self.runtime.docker('network', 'create', '--ipv6', self.name, json_output=False)
            self.created = True
            server = '''require "socket"; STDOUT.sync=true
servers=[]
[[Socket::AF_INET,"0.0.0.0","4"],[Socket::AF_INET6,"::","6"]].each do |family,host,label|
tcp=Socket.new(family,Socket::SOCK_STREAM,0); tcp.setsockopt(Socket::IPPROTO_IPV6,Socket::IPV6_V6ONLY,1) if family==Socket::AF_INET6; tcp.bind(Socket.sockaddr_in(45678,host)); tcp.listen(10)
udp=UDPSocket.new(family); udp.setsockopt(Socket::IPPROTO_IPV6,Socket::IPV6_V6ONLY,1) if family==Socket::AF_INET6; udp.bind(host,45679)
servers << Thread.new { loop { c,_=tcp.accept; c.close; puts "tcp"+label } }
servers << Thread.new { loop { udp.recvfrom(64); puts "udp"+label } }
end
puts "ready"; servers.each(&:join)'''
            self.listener = self.name
            self.runtime.docker('run', '--detach', '--pull=never', '--name', self.name,
                '--network', self.name, '--read-only', '--user=1000:1000', '--cap-drop=ALL', '--security-opt=no-new-privileges=true',
                '--pids-limit=16', '--memory=64m', '--cpus=0.25', '--log-driver=local', '--log-opt=max-size=64k', '--log-opt=max-file=1', '--log-opt=compress=false',
                '--entrypoint=/usr/bin/env', self.runtime.image, '-i', 'PATH=/usr/local/bin:/usr/bin:/bin', '/usr/local/bin/ruby', '-e', server,
                json_output=False)
            network = self.runtime.docker('inspect', self.listener)[0]['NetworkSettings']['Networks'][self.name]
            self.config = {'ipv4': network['IPAddress'], 'ipv6': network['GlobalIPv6Address'],
                           'bridge': network['Gateway'], 'port': 45678, 'dns_port': 45679}
            if not self.config['ipv4'] or not self.config['ipv6']:
                raise Refused('Controlled network families unavailable')
            ready_by = time.monotonic() + 5
            while self.events() != ['ready']:
                if time.monotonic() >= ready_by:
                    raise Refused('Controlled network listener unavailable')
                time.sleep(.05)
            client = '''require "socket"; require "json"; c=JSON.parse(ARGV[0]); [["ipv4",Socket::AF_INET],["ipv6",Socket::AF_INET6]].each do |key,family|
Socket.tcp(c[key],c["port"],connect_timeout: 1) { |s| s.write("fixed-positive") }
u=UDPSocket.new(family); u.send("fixed-positive",0,c[key],c["dns_port"]); u.close
end'''
            self.runtime.docker('run', '--rm', '--pull=never', '--network', self.name, '--read-only', '--user=1000:1000',
                '--cap-drop=ALL', '--security-opt=no-new-privileges=true', '--pids-limit=16', '--memory=64m', '--log-driver=none',
                '--entrypoint=/usr/bin/env', self.runtime.image, '-i', 'PATH=/usr/local/bin:/usr/bin:/bin', '/usr/local/bin/ruby', '-e', client,
                canonical(self.config).decode(), json_output=False)
            ready_by = time.monotonic() + 5
            while sorted(self.events()) != ['ready', 'tcp4', 'tcp6', 'udp4', 'udp6']:
                if time.monotonic() >= ready_by:
                    raise Refused('Controlled network positive operations failed')
                time.sleep(.05)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def events(self):
        return self.runtime.docker('logs', self.listener, json_output=False).splitlines()

    def __exit__(self, *_):
        if self.listener:
            command(['docker', 'rm', '--force', self.listener], timeout=10, env=self.runtime.env)
            self.listener = None
        if self.created:
            command(['docker', 'network', 'rm', self.name], timeout=10, env=self.runtime.env)
            self.created = False


def qualify(runtime, directory):
    suite = read_json((ASSETS / 'suite.json').read_bytes())
    sentinel = pathlib.Path(directory) / 'host-sentinel'
    sentinel.write_bytes(b'MERGABLE_SYNTHETIC_REPORT_AUTHORITY')
    before = digest(sentinel.read_bytes())
    cases = []
    effective_controls = None
    network = SyntheticNetwork(runtime).__enter__()
    network_input = canonical(network.config)
    previous_env = os.environ.get('MERGABLE_SYNTHETIC_SECRET')
    os.environ['MERGABLE_SYNTHETIC_SECRET'] = 'MERGABLE_SYNTHETIC_REPOSITORY_TOKEN'
    try:
        for name in ['usable', 'access'] + [key for key in suite['fixtures'] if key not in ('usable', 'access')]:
            fixture = suite['fixtures'][name]
            with tempfile.TemporaryDirectory(prefix='mergable-fixture-') as temporary:
                source = pathlib.Path(temporary)
                source.chmod(0o755)
                (source / 'script').mkdir()
                (source / SOURCE).write_text(fixture)
                case_input = network_input if name == 'network' else (canonical({'sentinel_path': str(sentinel.resolve()), 'host_pid': os.getpid()}) if name == 'access' else INPUT)
                record, payload = runtime.execute(source, case_input, cancel_after=0.25 if name == 'cancelled' else None)
                process = record['process']
                effective_controls = effective_controls or record['controls']
                passed = process['cleanup_complete'] and process['source_unchanged'] and not process['runtime_error'] and record['controls'] == effective_controls
                observed = {}
                if name in ('usable', 'access', 'network', 'privilege', 'pids', 'tmpfs'):
                    try:
                        observed = read_json(payload['stdout'])
                    except (ValueError, Refused):
                        observed = {}
                    expected = suite['expectations']
                    passed = passed and observed == expected[name] and process['exit_code'] == 0
                elif name == 'memory':
                    passed = passed and process['oom_killed'] and process['stop_reason'] is None
                elif name == 'output_limit':
                    passed = passed and process['stop_reason'] == 'output_limit' and sum(v['bytes'] for v in record['payloads'].values()) == 1048576
                elif name == 'cancelled':
                    passed = passed and process['stop_reason'] == 'cancelled'
                elif name == 'wall_timeout':
                    passed = passed and process['stop_reason'] == 'wall_timeout' and not process['oom_killed']
                elif name == 'stdio':
                    passed = passed and record['probe'] == 'observed_match'
                else:
                    passed = passed and record['probe'] != 'observed_match'
                cases.append({'id': name, 'fixture_sha256': digest(fixture.encode()), 'passed': bool(passed), 'observation': observed,
                              'process': process, 'payloads': record['payloads']})
        network_events = network.events()
        outside_network_denied = sorted(network_events) == ['ready', 'tcp4', 'tcp6', 'udp4', 'udp6']
    finally:
        network.__exit__(None, None, None)
        if previous_env is None:
            os.environ.pop('MERGABLE_SYNTHETIC_SECRET', None)
        else:
            os.environ['MERGABLE_SYNTHETIC_SECRET'] = previous_env
    return {'scope': 'hosted' if runtime.hosted else 'local_only', 'cases': cases, 'effective_controls': effective_controls,
            'network_observation': {'positive': ['ready', 'tcp4', 'tcp6', 'udp4', 'udp6'], 'after_restricted_cases': sorted(network_events)},
            'host_integrity': {'before_sha256': before, 'after_sha256': digest(sentinel.read_bytes())},
            'host_sentinel_unchanged': digest(sentinel.read_bytes()) == before, 'outside_network_denied': outside_network_denied,
            'cleanup_complete': all(case['process']['cleanup_complete'] for case in cases), 'fingerprint': runtime.fingerprint,
            'suite_sha256': digest((ASSETS / 'suite.json').read_bytes())}


def run_hosted(mode, output):
    bindings = read_json(os.environ['MERGABLE_INPUTS'])
    runtime_binding = read_json(bindings['runtime'])
    deadline = int(bindings['deadline'])
    allowance = 600 if mode == 'qualification' else 300
    if deadline < time.time() + 60 or bindings['workflow_sha'] != os.environ['GITHUB_WORKFLOW_SHA'] or bindings['requester'] != os.environ['GITHUB_ACTOR_ID']:
        raise Refused('Saved deadline or execution identity differs')
    if not re.fullmatch(r'[0-9a-f-]{36}', bindings['request']) or mode not in ('qualification', 'execution'):
        raise Refused('Invalid execution binding')
    runtime = Runtime(runtime_binding['image'], 'linux/amd64', time.monotonic() + min(allowance - 20, deadline - time.time()))
    if runtime.fingerprint['contract_sha256'] != runtime_binding['contract_sha256']:
        raise Refused('Runtime contract mismatch')
    provider = {'repository_id': int(os.environ['GITHUB_REPOSITORY_ID']), 'run_id': int(os.environ['GITHUB_RUN_ID']),
                'attempt': int(os.environ['GITHUB_RUN_ATTEMPT']), 'job_locator': os.environ['GITHUB_JOB'],
                'workflow_sha': os.environ['GITHUB_WORKFLOW_SHA']}
    report = {'schema': 1, 'mode': mode, 'binding': bindings, 'provider': provider, 'fingerprint': runtime.fingerprint}
    output = pathlib.Path(output)
    output.mkdir(mode=0o700)
    if mode == 'qualification':
        setup_sentinel = output / 'setup-sentinel'
        setup_sentinel.write_bytes(b'MERGABLE_SYNTHETIC_SETUP_AUTHORITY')
        setup_before = digest(setup_sentinel.read_bytes())
        os.environ['MERGABLE_SETUP_TRAP'] = str(setup_sentinel.resolve())
        with tempfile.TemporaryDirectory(prefix='mergable-setup-') as temporary:
            projection = stage(os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_WORKFLOW_SHA'], pathlib.Path(temporary) / 'candidate', os.environ['GH_TOKEN'], qualification=True)
            if projection['files'][0]['sha256'] != digest((ASSETS / 'fixture/script/total_cents.rb').read_bytes()):
                raise Refused('Setup projection differs')
        os.environ.pop('MERGABLE_SETUP_TRAP', None)
        setup_after = digest(setup_sentinel.read_bytes())
        if setup_before != setup_after:
            raise Refused('Candidate setup mutated the authenticated host')
        projection['host_sentinel_before'] = setup_before
        projection['host_sentinel_after'] = setup_after
        report['qualification'] = qualify(runtime, output)
        report['qualification']['source_setup'] = projection
    else:
        if runtime.fingerprint != runtime_binding['fingerprint']:
            raise Refused('Host fingerprint changed; requalification required')
        repository = runtime_binding['candidate_repository']
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', repository):
            raise Refused('Invalid source repository')
        with tempfile.TemporaryDirectory(prefix='mergable-stage-') as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o755)
            source = root / 'candidate'
            projection = stage(repository, bindings['candidate_sha'], source, os.environ['GH_TOKEN'])
            record, payloads = runtime.execute(source)
            report['source'] = projection
            report['execution'] = record
            for role, value in payloads.items():
                (output / (role + '.bin')).write_bytes(value)
    (output / 'report.json').write_bytes(canonical(report))



def main():
    if len(sys.argv) == 5 and sys.argv[1] == 'local-suite':
        runtime = Runtime(sys.argv[2], sys.argv[3], time.monotonic() + 160, hosted=False)
        report = qualify(runtime, sys.argv[4])
        (pathlib.Path(sys.argv[4]) / 'report.json').write_bytes(canonical(report))
    elif len(sys.argv) == 3 and sys.argv[1] in ('qualification', 'execution'):
        run_hosted(sys.argv[1], sys.argv[2])
    else:
        raise Refused('Unsupported controller operation')


if __name__ == '__main__':
    import signal
    def cancelled(signum, frame):
        raise Refused('Controller interrupted; no complete report')
    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGINT, cancelled)
    try:
        main()
    except (Refused, ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, Refused) else 'Restricted runtime refused incomplete or invalid execution.', file=sys.stderr)
        sys.exit(1)
