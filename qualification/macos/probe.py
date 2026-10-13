"""Hosted-runner-only qualification. Never import this module to run a probe locally."""
import contextlib
import errno
import json
import os
from pathlib import Path
import plistlib
import re
import resource
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

ROOT = Path('/private/tmp/swarma-capability')
USER = '_swarma_cap_probe'
OBSERVER = '_swarma_cap_observer'
ROWS = ('ACCT', 'EXEC', 'NET', 'DNS', 'PF', 'NPROC', 'MEM-RLIMIT',
        'MEM-WATCH', 'CPU-QOS', 'DISK', 'VIS', 'CRON', 'LAUNCHD', 'KILL', 'SOCK')
BOUNDS = {row: 120 for row in ROWS}
BOUNDS.update({'CPU-QOS': 180, 'DISK': 180, 'SOCK': 90})


def guard(env=None, major=None, euid=None):
    env = os.environ if env is None else env
    if (env.get('GITHUB_ACTIONS') != 'true' or
            env.get('RUNNER_ENVIRONMENT') != 'github-hosted' or
            env.get('RUNNER_OS') != 'macOS' or
            env.get('PROBE_RUNNER_LABEL') not in ('macos-14', 'macos-15')):
        raise RuntimeError('requires an authorized GitHub-hosted runner')
    if major is None:
        major = subprocess.check_output(['/usr/bin/sw_vers', '-productVersion'], text=True).split('.')[0]
    if str(major) != env['PROBE_RUNNER_LABEL'].split('-')[1]:
        raise RuntimeError('OS label mismatch')
    if (os.geteuid() if euid is None else euid) != 0:
        raise RuntimeError('requires root')


def redact(text):
    # Capture only test-owned process arguments. Sanitize diagnostics from OS tools.
    text = re.sub(r'/Users/[^/\s]+', '<runner-home>', str(text))
    text = re.sub(r'/home/[^/\s]+', '<runner-home>', text)
    text = re.sub(r'(?i)(host(?:name)?\s*[=:]\s*)\S+', r'\1<redacted>', text)
    return text[:12000]


def demote(uid):
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)


def spawn(argv, uid=None, stdin=None, stdout=subprocess.PIPE):
    def child():
        if uid is not None:
            demote(uid)
    return subprocess.Popen([str(x) for x in argv], stdin=stdin, stdout=stdout,
                            stderr=subprocess.PIPE, text=True, start_new_session=True,
                            preexec_fn=child if uid is not None else None,
                            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(ROOT / 'home'),
                                 'LANG': 'C', 'TMPDIR': str(ROOT / 'tmp')})


def stop(p):
    with contextlib.suppress(ProcessLookupError):
        os.killpg(p.pid, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        p.communicate(timeout=3)


def run(argv, uid=None, timeout=12, input=None):
    try:
        p = spawn(argv, uid=uid, stdin=subprocess.PIPE if input is not None else None)
    except OSError as e:
        return {'rc': 127, 'errno': e.errno, 'stderr': redact(e)}
    start = time.monotonic()
    try:
        out, err = p.communicate(input, timeout=timeout)
        result = {'rc': p.returncode, 'stdout': redact(out), 'stderr': redact(err),
                  'seconds': round(time.monotonic() - start, 4)}
        try:
            result['value'] = json.loads(out)
        except (ValueError, TypeError):
            pass
        if out.lstrip().startswith('<?xml'):
            try:
                result['plist'] = plistlib.loads(out.encode())
            except (ValueError, plistlib.InvalidFileException):
                pass
        return result
    except subprocess.TimeoutExpired:
        stop(p)
        return {'rc': 124, 'timeout': True, 'seconds': round(time.monotonic() - start, 4)}


def success(result):
    return result.get('rc') == 0


def denied(result):
    # A timeout, missing executable, syntax error or crash is not a denial.
    if result.get('rc') in (None, 0, 124, 127) or result.get('rc', 0) < 0:
        return False
    return bool(re.search(r'(?i)not permitted|permission denied|operation denied|not allowed|denied access',
                          result.get('stderr', '') + result.get('stdout', '')))


def deny_verdict(controls, attempts):
    if not controls or not attempts or not all(success(x) for x in controls):
        return 'unknown'
    if any(success(x) for x in attempts):
        return 'absent'
    return 'hard' if all(denied(x) for x in attempts) else 'unknown'


def emit(row, control, observed, verdict, evidence, expectation):
    return {'row': row, 'os': os.environ['PROBE_RUNNER_LABEL'], 'expectation': expectation,
            'control': control, 'observed': observed, 'verdict': verdict, 'evidence': evidence}


def binary(*args):
    return [ROOT / 'native', *args]


def profile(text):
    return ['/usr/bin/sandbox-exec', '-p', '(version 1) (allow default) ' + text]


def py(code, *args):
    return [sys.executable, '-c', code, *args]


def pid_inventory(uid):
    result = run(['/bin/ps', '-axo', 'uid=,pid='])
    if not success(result):
        raise RuntimeError('process inventory unreadable')
    found = []
    for line in result['stdout'].splitlines():
        fields = line.split()
        if len(fields) != 2 or not all(x.isdigit() for x in fields):
            raise RuntimeError('process inventory malformed')
        if int(fields[0]) == uid:
            found.append(int(fields[1]))
    return found


def kill_uid(uid):
    for pid in pid_inventory(uid):
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)


def create_account(name, uid, home):
    # Collision checks are read failures vs absence aware. No pre-existing account is touched.
    users = run(['/usr/bin/dscl', '.', '-list', '/Users', 'UniqueID'])
    groups = run(['/usr/bin/dscl', '.', '-list', '/Groups', 'PrimaryGroupID'])
    for listing in (users, groups):
        if not success(listing):
            raise RuntimeError('directory collision inventory unreadable')
        for line in listing['stdout'].splitlines():
            fields = line.split()
            if name in fields or str(uid) in fields:
                raise RuntimeError('qualification identity collision')
    (ROOT / ('created-' + name)).write_text(str(uid))  # obligation precedes first mutation
    commands = [
        ['/usr/bin/dscl', '.', '-create', '/Groups/' + name],
        ['/usr/bin/dscl', '.', '-create', '/Groups/' + name, 'PrimaryGroupID', str(uid)],
        ['/usr/bin/dscl', '.', '-create', '/Users/' + name],
    ]
    for key, value in {'UniqueID': str(uid), 'PrimaryGroupID': str(uid),
                       'UserShell': '/usr/bin/false', 'NFSHomeDirectory': str(home),
                       'IsHidden': '1', 'Password': '*'}.items():
        commands.append(['/usr/bin/dscl', '.', '-create', '/Users/' + name, key, value])
    for command in commands:
        result = run(command)
        if not success(result):
            raise RuntimeError('account creation failed: ' + json.dumps(result))
    home.mkdir(mode=0o700)
    os.chown(home, uid, uid)


@contextlib.contextmanager
def echo_server(kind, address):
    sock = socket.socket(socket.AF_UNIX if isinstance(address, str) else socket.AF_INET, kind)
    sock.bind(address)
    if kind == socket.SOCK_STREAM:
        sock.listen(10)
    sock.settimeout(0.2)
    done = threading.Event()
    def serve():
        while not done.is_set():
            try:
                if kind == socket.SOCK_STREAM:
                    client, _ = sock.accept()
                    with client:
                        client.settimeout(1)
                        data = client.recv(32)
                        client.sendall(data)
                else:
                    data, peer = sock.recvfrom(32)
                    sock.sendto(data, peer)
            except (OSError, TimeoutError):
                continue
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield sock.getsockname()
    finally:
        done.set()
        thread.join(timeout=2)
        sock.close()
        if isinstance(address, str):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(address)


CONNECT = '''import socket,sys
family = socket.AF_UNIX if sys.argv[1]=='unix' else socket.AF_INET
kind = socket.SOCK_DGRAM if sys.argv[1]=='udp' else socket.SOCK_STREAM
s=socket.socket(family,kind); s.settimeout(3)
target=sys.argv[2] if family==socket.AF_UNIX else (sys.argv[2],int(sys.argv[3]))
s.connect(target)
if sys.argv[1]!='tcp':
 s.send(b'qualification'); assert s.recv(32)==b'qualification'
print('connected')
'''


def network_attempts(uid, prefix=None):
    prefix = prefix or []
    # Only external TCP is used; UDP and ICMP controls stay on this runner.
    resolver = socket.getaddrinfo('www.apple.com', 443, socket.AF_INET, socket.SOCK_STREAM)
    ip = resolver[0][4][0]
    local = run(['/usr/sbin/ipconfig', 'getifaddr', 'en0'])
    local_ip = local.get('stdout', '').strip()
    if not success(local) or not re.fullmatch(r'\d+\.\d+\.\d+\.\d+', local_ip):
        local_ip = '127.0.0.1'
    unix = str(ROOT / 'declared.sock')
    with echo_server(socket.SOCK_STREAM, ('127.0.0.1', 0)) as tcp, \
            echo_server(socket.SOCK_DGRAM, ('0.0.0.0', 0)) as udp, \
            echo_server(socket.SOCK_STREAM, unix):
        os.chmod(unix, 0o666)
        commands = {'outbound_tcp': py(CONNECT, 'tcp', ip, '443'),
                    'outbound_udp_local_interface': py(CONNECT, 'udp', local_ip, str(udp[1])),
                    'loopback_tcp': py(CONNECT, 'tcp', tcp[0], str(tcp[1])),
                    'icmp_loopback': ['/sbin/ping', '-c', '1', '-W', '1000', '127.0.0.1'],
                    'declared_unix': py(CONNECT, 'unix', unix)}
        return {name: run(prefix + command, uid, timeout=7) for name, command in commands.items()}


def row_acct(cfg):
    uid = cfg['uid']
    identity = run(['/usr/bin/id', USER])
    launched = run(['/usr/bin/id'], uid)
    su = run(['/usr/bin/su', '-l', USER, '-c', '/usr/bin/id'])
    # Direct invocation of the configured shell; no pseudo-terminal/password guessing.
    shell = run(['/usr/bin/false'], uid)
    auth = run(['/usr/bin/dscl', '.', '-authonly', USER, 'qualification-invalid-password'])
    attrs = run(['/usr/bin/dscl', '.', '-read', '/Users/' + USER,
                 'UniqueID', 'PrimaryGroupID', 'UserShell', 'IsHidden', 'Password'])
    stat = (ROOT / 'home').stat()
    observed = {'su_login': su, 'shell': shell, 'password_auth': auth, 'attributes': attrs,
                'home_mode': oct(stat.st_mode & 0o777), 'home_entries': len(list((ROOT / 'home').iterdir())),
                'supplementary_groups': run(['/usr/bin/id', '-G'], uid)}
    groups = observed['supplementary_groups']
    hard = (success(identity) and success(launched) and success(attrs) and
            su['rc'] == 1 and shell['rc'] == 1 and auth['rc'] != 0 and
            success(groups) and groups['stdout'].strip() == str(uid) and
            observed['home_mode'] == '0o700' and observed['home_entries'] == 0)
    return emit('ACCT', {'id_record': identity, 'root_launcher_id': launched}, observed,
                'hard' if hard else 'unknown',
                'No graphical/SSH interactive login attempted; false shell, su -l and disabled password tested.',
                'Hidden UID >=30000, private empty home, own group, no supplementary groups, login refused')


def row_exec(cfg):
    uid = cfg['uid']
    copy = ROOT / 'home' / 'echo-copy'
    shutil.copy('/bin/echo', copy)
    os.chown(copy, uid, uid)
    os.chmod(copy, 0o755)
    commands = [['/bin/echo', 'allowlisted'], ['/usr/bin/perl', '-e', 'print "interpreter\\n"'],
                [copy, 'writable-copy']]
    controls = [run(cmd, uid) for cmd in commands]
    sb = profile('(deny process-exec) (allow process-exec (literal "/bin/echo"))')
    observed = [run(sb + cmd, uid) for cmd in commands]
    verdict = deny_verdict(controls, observed[1:]) if success(observed[0]) else 'unknown'
    copy.unlink()
    return emit('EXEC', controls, {'allowlisted': observed[0], 'interpreter': observed[1],
                                 'writable_copy': observed[2]}, verdict,
                'Exact /bin/echo allowlist; same binaries executed without sandbox as controls.',
                'Allowlisted binary succeeds; interpreter and writable binary copy refuse')


def row_net(cfg):
    control = network_attempts(cfg['uid'])
    unix = ROOT / 'declared.sock'
    sb = profile('(deny network*) (allow network* (local unix-socket (literal "' + str(unix) +
                 '")) (remote unix-socket (literal "' + str(unix) + '")))')
    observed = network_attempts(cfg['uid'], sb)
    keys = [k for k in control if k != 'declared_unix']
    verdict = deny_verdict([control[k] for k in keys], [observed[k] for k in keys])
    if not success(control['declared_unix']) or not success(observed['declared_unix']):
        verdict = 'unknown'
    return emit('NET', control, observed, verdict,
                'IPv4 only; UDP echo on runner interface (no external UDP service), ICMP loopback. '
                'IPv6, existing sockets, QUIC and raw packet bypasses not measured.',
                'Deny TCP/UDP/loopback/ICMP while allowing one declared Unix socket')


def row_dns(cfg):
    control = run(binary('resolve'), cfg['uid'])
    sb = profile('(deny mach-lookup (global-name "com.apple.mDNSResponder")) '
                 '(deny network* (remote unix-socket (literal "/private/var/run/mDNSResponder")))')
    observed = run(sb + binary('resolve'), cfg['uid'])
    verdict = 'unknown'
    if success(control) and 'value' in observed:
        verdict = 'absent' if observed['value'].get('resolved') else 'hard'
    return emit('DNS', control, observed, verdict,
                'Native getaddrinfo through system resolver; cached answers count as a bypass. '
                'No claim about every resolver service or direct DNS.',
                'Resolver Mach service/socket denial refuses system name resolution')


def pf_restore():
    marker = ROOT / 'pf-active'
    if not marker.exists():
        return []
    results = [run(['/sbin/pfctl', '-a', anchor, '-F', 'all'])
               for anchor in ('swarma-qualification-deny', 'swarma-qualification-early')]
    results.append(run(['/sbin/pfctl', '-f', ROOT / 'pf-original.conf']))
    token_file = ROOT / 'pf-token'
    if token_file.exists():
        results.append(run(['/sbin/pfctl', '-X', token_file.read_text().strip()]))
    for option, filename in (('-sr', 'pf-original-filter'), ('-sn', 'pf-original-nat')):
        current = run(['/sbin/pfctl', option])
        current['matches_original'] = success(current) and current['stdout'] == (ROOT / filename).read_text()
        if not current['matches_original']:
            current['rc'] = 1
        results.append(current)
    if all(success(x) for x in results):
        marker.unlink()
    return results


def row_pf(cfg):
    control = network_attempts(cfg['uid'])
    original = run(['/sbin/pfctl', '-sr'])
    nat = run(['/sbin/pfctl', '-sn'])
    if not success(original) or not success(nat):
        return emit('PF', control, original, 'unknown', 'PF rules could not be read.', 'UID TCP/UDP deny and precedence detection')
    (ROOT / 'pf-original-filter').write_text(original['stdout'])
    (ROOT / 'pf-original-nat').write_text(nat['stdout'])
    (ROOT / 'pf-original.conf').write_text(nat['stdout'] + original['stdout'])
    # Hosted ephemeral runner only: temporary root filter contains two named anchors.
    (ROOT / 'pf-active').touch()
    root_rules = ROOT / 'pf-test.conf'
    root_rules.write_text('anchor "swarma-qualification-early"\nanchor "swarma-qualification-deny"\n')
    deny_rules = ROOT / 'pf-deny.conf'
    deny_rules.write_text('block drop out quick proto { tcp udp } all user ' + str(cfg['uid']) + '\n')
    early_rules = ROOT / 'pf-early.conf'
    early_rules.write_text('pass out quick proto { tcp udp } all\n')
    setup = [run(['/sbin/pfctl', '-f', root_rules]),
             run(['/sbin/pfctl', '-a', 'swarma-qualification-deny', '-f', deny_rules])]
    enabled = run(['/sbin/pfctl', '-E'])
    setup.append(enabled)
    match = re.search(r'Token\s*:\s*(\d+)', enabled.get('stderr', '') + enabled.get('stdout', ''))
    if match:
        (ROOT / 'pf-token').write_text(match[1])
    observed = {'setup': setup}
    verdict = 'unknown'
    try:
        if all(success(x) for x in setup):
            observed['uid_denied'] = network_attempts(cfg['uid'])
            observed['runner_control'] = network_attempts(cfg['runner_uid'])
            observed['earlier_pass_setup'] = run(['/sbin/pfctl', '-a', 'swarma-qualification-early', '-f', early_rules])
            observed['earlier_pass_uid_probe'] = network_attempts(cfg['uid'])
            keys = ('outbound_tcp', 'outbound_udp_local_interface')
            blocked = all(not success(observed['uid_denied'][k]) and
                          observed['uid_denied'][k].get('rc') != 124 for k in keys)
            controls_ok = all(success(control[k]) and success(observed['runner_control'][k]) for k in keys)
            precedence = all(success(observed['earlier_pass_uid_probe'][k]) for k in keys)
            # Timed TCP/UDP attempts are evidence only with valid UID/runner controls and loaded rules.
            verdict = 'hard' if blocked and controls_ok and precedence else 'unknown'
            if controls_ok and any(success(observed['uid_denied'][k]) for k in keys):
                verdict = 'absent'
            observed['active_precedence_violation_detected'] = precedence
    finally:
        observed['restore'] = pf_restore()
        if not all(success(x) for x in observed['restore']):
            verdict = 'unknown'
    return emit('PF', control, observed, verdict,
                'Dedicated anchors; new sockets for every attempt. ICMP and loopback recorded separately. '
                'Original loaded root NAT/filter rules restored and compared; existing anchors left intact, '
                'enable reference released. PF state table is not snapshotted.',
                'UID TCP/UDP deny, runner traffic allowed, active probe detects earlier quick pass')


def row_nproc(cfg):
    control = run(binary('nproc', '0'), cfg['uid'], timeout=20)
    observed = {str(n): run(binary('nproc', str(n)), cfg['uid'], timeout=20) for n in (16, 8)}
    values = [x.get('value', {}) for x in observed.values()]
    hard = (success(control) and control.get('value', {}).get('children') == 100 and
            all(success(x) for x in observed.values()) and
            all(v.get('errno') == errno.EAGAIN and 0 < v.get('children', 101) < v.get('limit', 0) for v in values) and
            values[1].get('children', 100) < values[0].get('children', 0))
    return emit('NPROC', control, observed, 'hard' if hard else 'unknown',
                'RLIMIT_NPROC hard+soft set before fork; 100 attempts, children killed/reaped. '
                'Limit belongs to a process, counts the UID; every admitted launch must inherit it. '
                'No persistent account-wide launch policy is installed.',
                'A narrowed per-UID-counted inherited process limit causes EAGAIN')


def row_mem_rlimit(cfg):
    control = run(binary('memory', 'control'), cfg['uid'], timeout=30)
    observed = {kind: run(binary('memory', kind), cfg['uid'], timeout=30) for kind in ('as', 'data')}
    statuses = {}
    for kind, result in observed.items():
        value = result.get('value', {})
        if not success(control) or control.get('value', {}).get('bytes') != 1 << 30 or not success(result):
            statuses[kind] = 'unknown'
        elif value.get('bytes', 0) > 128 << 20:
            statuses[kind] = 'absent'
        elif value.get('errno') == errno.ENOMEM:
            statuses[kind] = 'hard'
        else:
            statuses[kind] = 'unknown'
    observed['subverdicts'] = statuses
    verdict = 'hard' if all(x == 'hard' for x in statuses.values()) else (
        'absent' if all(x == 'absent' for x in statuses.values()) else 'unknown')
    return emit('MEM-RLIMIT', control, observed, verdict,
                'Native malloc+memset, 16 MiB chunks, 128 MiB limit, 1 GiB allocation bound; per process only.',
                'RLIMIT_AS and RLIMIT_DATA prevent touched allocations beyond their limits')


def rss(pid):
    result = run(['/bin/ps', '-o', 'rss=', '-p', str(pid)], timeout=2)
    if success(result) and result['stdout'].strip().isdigit():
        return int(result['stdout'].strip()) * 1024
    if result.get('rc') == 1 and not result.get('stdout', '').strip():
        return None
    raise RuntimeError('RSS read failed or malformed')


def watch_trial(uid, interval, enabled):
    logfile = ROOT / ('grow-' + str(interval) + '-' + str(enabled) + '.jsonl')
    peak = 0
    samples = []
    threshold = 1 << 30
    crossed = killed = None
    with logfile.open('w') as log:
        p = spawn(binary('grow'), uid, stdout=log)
        start = time.monotonic()
        try:
            while p.poll() is None and time.monotonic() - start < 25:
                value = rss(p.pid)
                elapsed = time.monotonic() - start
                if value is not None:
                    peak = max(peak, value)
                    samples.append({'seconds': round(elapsed, 4), 'rss_bytes': value})
                    if enabled and value >= threshold:
                        crossed = time.monotonic()
                        os.kill(p.pid, signal.SIGKILL)
                        p.wait(timeout=3)
                        killed = time.monotonic()
                        break
                time.sleep(interval)
            if p.poll() is None:
                stop(p)
            rc = p.wait(timeout=3)
        finally:
            stop(p)
    allocations = [json.loads(x) for x in logfile.read_text().splitlines()]
    return {'rc': rc, 'sample_interval_seconds': interval, 'samples': samples,
            'peak_sampled_rss_bytes': peak, 'last_allocation_bytes': allocations[-1]['bytes'] if allocations else 0,
            'kill_after_detection_seconds': None if killed is None else round(killed - crossed, 4),
            'threshold_crossing_to_detection_bound_seconds': interval,
            'elapsed_seconds': round(time.monotonic() - start, 4)}


def row_mem_watch(cfg):
    control = watch_trial(cfg['uid'], .25, False)
    observed = {str(i): watch_trial(cfg['uid'], i, True) for i in (.25, 1.0)}
    soft = control['rc'] == 0 and control['last_allocation_bytes'] == 60 * (50 << 20) and all(
        r['rc'] == -signal.SIGKILL and r['kill_after_detection_seconds'] is not None for r in observed.values())
    return emit('MEM-WATCH', control, observed, 'soft' if soft else 'unknown',
                '50 MiB touched every 250 ms (200 MiB/s nominal), 3000 MiB bound; threshold 1 GiB. '
                'Peak is sampled, not continuous; kill latency starts at detection, true crossing lies between samples. '
                'Single allocator demonstration, not a deployed aggregate-UID watcher.',
                'Root RSS watcher kills above 1 GiB at 250 ms and 1 s sampling')


def row_cpu(cfg):
    baseline = run(binary('bench'), cfg['runner_uid'], timeout=20)
    measurements = {}
    cores = os.cpu_count() or 1
    for mode in ('default', 'background'):
        burners = []
        try:
            for _ in range(cores):
                prefix = ['/usr/bin/taskpolicy', '-b'] if mode == 'background' else []
                burners.append(spawn(prefix + binary('burn'), cfg['uid']))
            time.sleep(.4)
            measurements[mode] = run(binary('bench'), cfg['runner_uid'], timeout=20)
            measurements[mode]['burners_alive_before_stop'] = sum(p.poll() is None for p in burners)
        finally:
            for p in burners:
                stop(p)
    cpu_control = run(binary('cpu'), cfg['uid'], timeout=15)
    cpu_limit = run(binary('cpu', 'limit'), cfg['uid'], timeout=15)
    observed = {'cores': cores, 'foreground_benchmark': measurements, 'rlimit_cpu': cpu_limit,
                'rlimit_cpu_verdict': 'hard' if success(cpu_control) and cpu_limit['rc'] in
                (-signal.SIGXCPU, -signal.SIGKILL) else 'unknown'}
    qualified = success(baseline) and all(success(x) and x['burners_alive_before_stop'] == cores
                                         for x in measurements.values())
    return emit('CPU-QOS', {'foreground_alone': baseline, 'rlimit_cpu_unrestricted': cpu_control},
                observed, 'soft' if qualified else 'unknown',
                'One 8 s bounded burner/core; fixed 500 million iteration foreground workload. '
                'Scheduling measurements do not prove a CPU-share ceiling; RLIMIT_CPU is per process. IO not measured.',
                'Background taskpolicy changes contention; per-process RLIMIT_CPU enforces CPU time')


WRITE = '''import json,os,sys
path=sys.argv[1]; total=0; error=0
try:
 with open(path,'wb',buffering=0) as f:
  for i in range(96):
   data=os.urandom(4*1024*1024)
   view=memoryview(data)
   while view:
    n=f.write(view); total+=n; view=view[n:]
   os.fsync(f.fileno())
except OSError as e: error=e.errno
print(json.dumps({'bytes':total,'errno':error,'bound_bytes':384*1024*1024}))
'''


def row_disk(cfg):
    # A disposable disk image keeps all quota mutations off the runner's boot container.
    image = ROOT / 'quota.dmg'
    create = run(['/usr/bin/hdiutil', 'create', '-size', '1g', '-fs', 'APFS', '-volname',
                  'SwarmaQualificationBase', image], timeout=45)
    attached = run(['/usr/bin/hdiutil', 'attach', '-nomount', '-plist', image], timeout=30)
    observed = {'image_create': create, 'image_attach': attached}
    control = {}
    verdict = 'unknown'
    if not success(create) or not success(attached):
        return emit('DISK', control, observed, verdict, 'Disposable APFS image setup failed.', 'APFS volume quota and per-user quota support')
    devices = attached['plist']['system-entities']
    device = devices[0]['dev-entry']
    (ROOT / 'disk-device').write_text(device)
    listing = run(['/usr/sbin/diskutil', 'apfs', 'list', '-plist'])
    observed['apfs_list_rc'] = listing['rc']
    if not success(listing):
        return emit('DISK', control, observed, verdict, 'APFS container inventory failed.', 'APFS quota')
    containers = listing['plist']['Containers']
    container = next((c['ContainerReference'] for c in containers if any(
        p['DeviceIdentifier'] == device.replace('/dev/', '') + 's1' or
        '/dev/' + p['DeviceIdentifier'] == device for p in c.get('PhysicalStores', []))), None)
    if container is None:
        # hdiutil may return the physical partition separately, map exact attached device set.
        ids = {x['dev-entry'].replace('/dev/', '') for x in devices}
        container = next((c['ContainerReference'] for c in containers if any(
            p['DeviceIdentifier'] in ids for p in c.get('PhysicalStores', []))), None)
    if container is None:
        return emit('DISK', control, observed, verdict, 'Could not map disposable container.', 'APFS quota')
    mount = ROOT / 'quota-mount'
    mount.mkdir(exist_ok=True)
    added = run(['/usr/sbin/diskutil', 'apfs', 'addVolume', container, 'APFS',
                 'SwarmaQualificationQuota', '-quota', '256m', '-mountpoint', mount], timeout=30)
    observed['add_volume'] = added
    if success(added):
        os.chmod(mount, 0o777)
        control['below_and_past_limit_unrestricted'] = run(py(WRITE, str(ROOT / 'home' / 'control-write')), cfg['uid'], timeout=40)
        observed['quota_write'] = run(py(WRITE, str(mount / 'quota-write')), cfg['uid'], timeout=40)
        value = observed['quota_write'].get('value', {})
        if success(control['below_and_past_limit_unrestricted']) and control['below_and_past_limit_unrestricted'].get('value', {}).get('bytes') == 384 << 20:
            if value.get('errno') in (errno.ENOSPC, errno.EDQUOT) and 0 < value.get('bytes', 0) < 384 << 20:
                verdict = 'hard'
            elif value.get('bytes') == 384 << 20:
                verdict = 'absent'
        observed['per_user_quota_enable'] = run(['/usr/sbin/quotaon', '-u', str(mount)])
        observed['per_user_quota_status'] = run(['/usr/bin/quota', '-u', USER])
        observed['per_user_quota_verdict'] = 'unknown'
        quota_error = observed['per_user_quota_enable'].get('stderr', '')
        if re.search(r'(?i)not supported|operation not supported', quota_error):
            observed['per_user_quota_verdict'] = 'absent'
        info = run(['/usr/sbin/diskutil', 'info', '-plist', mount])
        if success(info):
            volume = info['plist']['DeviceIdentifier']
            observed['delete_volume'] = run(['/usr/sbin/diskutil', 'apfs', 'deleteVolume', volume], timeout=30)
        (ROOT / 'home' / 'control-write').unlink(missing_ok=True)
    observed['detach'] = run(['/usr/bin/hdiutil', 'detach', device], timeout=30)
    if success(observed['detach']):
        (ROOT / 'disk-device').unlink()
    else:
        verdict = 'unknown'
    return emit('DISK', control, observed, verdict,
                '256 MiB volume quota on a 1 GiB disposable APFS image, random-data writes bounded at 384 MiB. '
                'Volume quota is aggregate, not per UID. quotaon is a support probe, no per-user enforcement claim.',
                'Volume quota stops writes; separately establish APFS per-user quota support')


def row_vis(cfg):
    targets = {}
    procs = []
    try:
        for name, uid in (('runner', cfg['runner_uid']), ('probe', cfg['uid'])):
            p = spawn(py('import time; time.sleep(45)', 'swarma-visibility-marker'), uid)
            procs.append(p)
            targets[name] = p.pid
        time.sleep(.3)
        controls = {name: run(['/bin/ps', '-p', str(pid), '-o', 'pid=,uid=,pcpu=,rss=,args='])
                    for name, pid in targets.items()}
        observed = {'probe_reads_runner_ps': run(['/bin/ps', '-p', str(targets['runner']), '-o', 'pid=,uid=,pcpu=,rss=,args='], cfg['uid']),
                    'observer_reads_probe_ps': run(['/bin/ps', '-p', str(targets['probe']), '-o', 'pid=,uid=,pcpu=,rss='], cfg['observer_uid'])}
        top = run(['/usr/bin/top', '-l', '1', '-pid', str(targets['runner']), '-stats', 'pid,cpu,mem'], cfg['uid'])
        top['stdout'] = '\n'.join(line for line in top.get('stdout', '').splitlines()
                                  if re.match(r'\s*' + str(targets['runner']) + r'\s', line))
        observed['probe_reads_runner_top'] = top
        visible = success(observed['probe_reads_runner_ps']) and 'swarma-visibility-marker' in observed['probe_reads_runner_ps'].get('stdout', '')
        return emit('VIS', controls, observed, 'absent' if visible else 'unknown',
                    'Only controlled foreign process arguments captured; service observer has a separate non-root UID. '
                    'Visibility verdict describes confidentiality, successful observer sampling describes privilege.',
                    'Measure foreign process arguments/CPU/RSS and least-privilege UID sampler')
    finally:
        for p in procs:
            stop(p)


def save_deny(name):
    path = Path('/etc/' + name)
    backup = ROOT / (name + '.backup')
    if path.exists():
        shutil.copy2(path, backup)
    (ROOT / (name + '.saved')).write_text('existing' if path.exists() else 'absent')


def restore_deny(name):
    path = Path('/etc/' + name)
    marker = ROOT / (name + '.saved')
    if marker.exists():
        if marker.read_text() == 'existing':
            shutil.copy2(ROOT / (name + '.backup'), path)
        else:
            path.unlink(missing_ok=True)
        marker.unlink()


def row_cron(cfg):
    for name in ('cron.deny', 'at.deny'):
        save_deny(name)
        Path('/etc/' + name).write_text('')
    controls = {'crontab': run(['/usr/bin/crontab', '-'], cfg['uid'], input='# qualification: no jobs\n'),
                'at': run(['/usr/bin/at', 'now', '+', '1', 'hour'], cfg['uid'], input='/usr/bin/true\n')}
    for name in ('cron.deny', 'at.deny'):
        Path('/etc/' + name).write_text(USER + '\n')
    observed = {'crontab': run(['/usr/bin/crontab', '-'], cfg['uid'], input='# qualification: no jobs\n'),
                'at': run(['/usr/bin/at', 'now', '+', '1', 'hour'], cfg['uid'], input='/usr/bin/true\n')}
    # Root removal works even while deny files are present.
    observed['remove_crontab'] = run(['/usr/bin/crontab', '-u', USER, '-r'])
    jobs = []
    for result in (controls['at'], observed['at']):
        jobs.extend(re.findall(r'\bjob\s+(\d+)', result.get('stderr', '') + result.get('stdout', '')))
    observed['remove_at_jobs'] = [run(['/usr/bin/atrm', job]) for job in jobs]
    for name in ('cron.deny', 'at.deny'):
        restore_deny(name)
    verdict = deny_verdict(list(controls.values()), [observed['crontab'], observed['at']])
    return emit('CRON', controls, observed, verdict,
                'Empty crontab and at true job one hour away; removed immediately. Existing deny files restored. '
                'Scheduler disabled or pre-existing allow files can invalidate a positive control.',
                'cron.deny and at.deny refuse same commands that succeeded without restriction')


def row_launchd(cfg):
    label = 'works.swarma.qualification'
    plist = ROOT / 'job.plist'
    marker = ROOT / 'tmp' / 'launchd-marker'
    plist.write_bytes(plistlib.dumps({'Label': label, 'ProgramArguments': ['/bin/sh', '-c',
                     'umask 000; echo started >> ' + str(marker) + '; exec /bin/sleep 30'],
                     'KeepAlive': True, 'RunAtLoad': True}))
    domains = {d: run(['/bin/launchctl', 'print', d + '/' + str(cfg['uid'])]) for d in ('user', 'gui')}
    control = run(['/bin/launchctl', 'bootstrap', 'user/' + str(cfg['runner_uid']), plist], cfg['runner_uid'])
    time.sleep(.5)
    control['job_lookup'] = run(['/bin/launchctl', 'print', 'user/' + str(cfg['runner_uid']) + '/' + label], cfg['runner_uid'])
    control['job_lookup']['stdout'] = ''  # launchd environment is not public evidence
    control['bootout'] = run(['/bin/launchctl', 'bootout', 'user/' + str(cfg['runner_uid']) + '/' + label])
    marker.unlink(missing_ok=True)
    observed = {'domains_before': {k: {'rc': v['rc'], 'stderr': v.get('stderr', '')} for k, v in domains.items()},
                'bootstrap_user': run(['/bin/launchctl', 'bootstrap', 'user/' + str(cfg['uid']), plist], cfg['uid'])}
    time.sleep(.5)
    observed['before_stop'] = pid_inventory(cfg['uid'])
    kill_uid(cfg['uid'])
    time.sleep(2)
    observed['after_stop'] = pid_inventory(cfg['uid'])
    observed['marker_lines'] = len(marker.read_text().splitlines()) if marker.exists() else 0
    observed['bootout'] = run(['/bin/launchctl', 'bootout', 'user/' + str(cfg['uid']) + '/' + label])
    kill_uid(cfg['uid'])
    verdict = 'unknown'
    if success(control) and success(observed['bootstrap_user']) and observed['after_stop']:
        verdict = 'absent'
    # A missing domain is an observed configuration, not proof all persistence paths refuse.
    return emit('LAUNCHD', control, observed, verdict,
                'Hidden user never interactively logged in. User and gui domain existence recorded, user-domain '
                'KeepAlive bootstrap tried as that UID; root cleanup bootout. Other domain creation APIs not covered.',
                'Probe UID cannot bootstrap a persistent KeepAlive user-domain job')


def row_kill(cfg):
    commands = {'normal': ['/bin/sleep', '30'], 'double_fork_setsid': binary('escape'),
                'nohup': ['/usr/bin/nohup', '/bin/sleep', '30']}
    controls = {}
    procs = []
    try:
        for name, command in commands.items():
            p = spawn(command, cfg['uid'])
            procs.append(p)
            time.sleep(.2)
            controls[name] = {'alive': p.poll() is None, 'rc': p.poll()}
        before = pid_inventory(cfg['uid'])
        kill_uid(cfg['uid'])
        for p in procs:
            with contextlib.suppress(subprocess.TimeoutExpired):
                p.wait(timeout=3)
        quiet = []
        start = time.monotonic()
        for index in range(21):
            time.sleep(max(0, start + index * .25 - time.monotonic()))
            quiet.append({'seconds': round(time.monotonic() - start, 3), 'pids': pid_inventory(cfg['uid'])})
        hard = len(before) >= 3 and controls['normal']['alive'] and controls['nohup']['alive'] and controls['double_fork_setsid']['rc'] == 0 and all(not x['pids'] for x in quiet)
        return emit('KILL', {'spawn': controls, 'uid_processes_before': before}, {'quiet_samples': quiet},
                    'hard' if hard else 'unknown',
                    'Root signals every PID in fresh UID inventory, including escaped/nohup children; '
                    '5 s quiet sampling at 250 ms. No claim about PID reuse races or unkillable kernel tasks.',
                    'Account-wide stop finds zero UID processes throughout a 5 s quiet period')
    finally:
        for p in procs:
            stop(p)
        kill_uid(cfg['uid'])


SOCKET_CONNECT = '''import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(.25)
try:
 s.connect(sys.argv[1]);print('connected')
except OSError as e:
 print('errno='+str(e.errno));sys.exit(1)
'''


def row_sock(cfg):
    owned = str(ROOT / 'foreign.sock')
    with echo_server(socket.SOCK_STREAM, owned):
        os.chown(owned, cfg['runner_uid'], os.stat(owned).st_gid)
        os.chmod(owned, 0o666)
        control = run(py(CONNECT, 'unix', owned), cfg['uid'])
        os.chmod(owned, 0o600)
        observed = {'foreign_0600': run(py(CONNECT, 'unix', owned), cfg['uid'])}
    sockets = set()
    errors = []
    roots = ('/var/run', '/private/var/run', '/tmp')
    import stat
    def error(e):
        errors.append(redact(e))
    for root in roots:
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=error):
            # No symlink traversal; run paths canonicalized to avoid duplicate attempts.
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(directory, d))]
            for name in files:
                path = os.path.join(directory, name)
                try:
                    if stat.S_ISSOCK(os.lstat(path).st_mode):
                        sockets.add(os.path.realpath(path))
                except OSError as e:
                    errors.append(redact(e))
    results = []
    for path in sorted(sockets)[:100]:
        result = run(py(SOCKET_CONNECT, path), cfg['uid'], timeout=2)
        results.append({'path': redact(path), **result})
    observed.update({'inventory': results, 'enumerated': len(sockets), 'attempted': len(results),
                     'coverage': str(len(results)) + '/' + str(len(sockets)), 'walk_errors': errors,
                     'reachable': [x['path'] for x in results if success(x)]})
    verdict = deny_verdict([control], [observed['foreign_0600']])
    if errors or len(results) != len(sockets):
        verdict = 'unknown'
    return emit('SOCK', control, observed, verdict,
                '0600 denial controls same foreign-owned socket at 0666. Inventory connects only, no service payload. '
                'Stream sockets only, no symlink traversal, 100-path cap; datagram sockets and other roots unmeasured. '
                'Foreign socket verdict does not attest an approved deployment socket set.',
                'Foreign 0600 socket refused; enumerate reachable Unix stream sockets in three fixed roots')


FUNCTIONS = dict(zip(ROWS, (row_acct, row_exec, row_net, row_dns, row_pf, row_nproc,
                           row_mem_rlimit, row_mem_watch, row_cpu, row_disk, row_vis,
                           row_cron, row_launchd, row_kill, row_sock)))


def cleanup(cfg):
    results = []
    for uid in (cfg['uid'], cfg['observer_uid']):
        try:
            kill_uid(uid)
        except Exception as e:
            results.append({'cleanup_error': redact(e)})
    results.extend(pf_restore())
    for name in ('cron.deny', 'at.deny'):
        restore_deny(name)
    results.append(run(['/bin/launchctl', 'bootout', 'user/' + str(cfg['uid']) + '/works.swarma.qualification']))
    results.append(run(['/bin/launchctl', 'bootout', 'user/' + str(cfg['runner_uid']) + '/works.swarma.qualification']))
    results.append(run(['/usr/bin/crontab', '-u', USER, '-r']))
    jobs = run(['/usr/bin/atq'], cfg['uid'])
    for line in jobs.get('stdout', '').splitlines():
        fields = line.split()
        if fields and fields[0].isdigit():
            results.append(run(['/usr/bin/atrm', fields[0]]))
    disk = ROOT / 'disk-device'
    if disk.exists():
        results.append(run(['/usr/bin/hdiutil', 'detach', '-force', disk.read_text()], timeout=30))
    for name in (USER, OBSERVER):
        if (ROOT / ('created-' + name)).exists():
            results.append(run(['/usr/bin/dscl', '.', '-delete', '/Users/' + name]))
            results.append(run(['/usr/bin/dscl', '.', '-delete', '/Groups/' + name]))
    # Keep no test accounts, jobs, mounts or fixture files after the evidence is copied.
    checks = {'remaining_uid_processes': {str(uid): pid_inventory(uid) for uid in (cfg['uid'], cfg['observer_uid'])},
              'accounts_removed': {name: run(['/usr/bin/id', name]) for name in (USER, OBSERVER)},
              'pf_restore_pending': (ROOT / 'pf-active').exists()}
    return {'actions': results, 'checks': checks}


def main():
    guard()
    if len(sys.argv) == 3 and sys.argv[1] == '--row':
        cfg = json.loads((ROOT / 'config.json').read_text())
        print(json.dumps(FUNCTIONS[sys.argv[2]](cfg)))
        return
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    if ROOT.exists():
        raise RuntimeError('fixed qualification root already exists; refusing to overwrite')
    ROOT.mkdir(mode=0o755)
    os.chmod(ROOT, 0o755)
    cfg = {'uid': 39001, 'observer_uid': 39002, 'runner_uid': int(os.environ.get('SUDO_UID', '501'))}
    # sudo env can omit SUDO_UID: get ownership of checked-out driver instead.
    cfg['runner_uid'] = Path(__file__).stat().st_uid
    if cfg['runner_uid'] == 0:
        raise RuntimeError('runner user must be non-root')
    (ROOT / 'config.json').write_text(json.dumps(cfg))
    (ROOT / 'tmp').mkdir(mode=0o777)
    os.chmod(ROOT / 'tmp', 0o777)
    shutil.copy(__file__, ROOT / 'probe.py')
    records = []
    interrupted = False
    def terminate(signum, frame):
        raise RuntimeError('interrupted by signal ' + str(signum))
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        create_account(USER, cfg['uid'], ROOT / 'home')
        create_account(OBSERVER, cfg['observer_uid'], ROOT / 'observer-home')
        build = run(['/usr/bin/clang', '-O2', '-Wall', '-Wextra', '-Werror',
                     Path(__file__).with_name('native.c'), '-o', ROOT / 'native'], timeout=60)
        (out / 'build.json').write_text(json.dumps(build, indent=2))
        if not success(build):
            raise RuntimeError('native workload build failed')
        for row in ROWS:
            command = [sys.executable, ROOT / 'probe.py', '--row', row]
            p = subprocess.Popen([str(x) for x in command], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, start_new_session=True)
            try:
                stdout, stderr = p.communicate(timeout=BOUNDS[row])
                if p.returncode:
                    raise RuntimeError('row exit ' + str(p.returncode) + ': ' + redact(stderr))
                record = json.loads(stdout)
            except Exception as e:
                stop(p)
                record = emit(row, {}, {'error': redact(e)}, 'unknown',
                              'Row failed or reached its bounded timeout; no capability inferred.',
                              'Measure the brief row with a successful positive control')
            records.append(record)
            (out / (row + '.json')).write_text(json.dumps(record, indent=2) + '\n')
            with (out / 'results.jsonl').open('a') as results:
                results.write(json.dumps(record) + '\n')
            print(json.dumps(record), flush=True)
            kill_uid(cfg['uid'])
    except Exception as e:
        interrupted = True
        (out / 'harness-error.json').write_text(json.dumps({'error': redact(e)}))
    finally:
        for row in ROWS:
            if row not in {r['row'] for r in records}:
                record = emit(row, {}, {'not_measured': True}, 'unknown',
                              'Harness setup/interruption prevented measurement.', 'Measure brief row')
                records.append(record)
                with (out / 'results.jsonl').open('a') as results:
                    results.write(json.dumps(record) + '\n')
        cleaned = cleanup(cfg)
        (out / 'cleanup.json').write_text(json.dumps(cleaned, indent=2) + '\n')
        metadata = {'os': os.environ['PROBE_RUNNER_LABEL'],
                    'version': subprocess.check_output(['/usr/bin/sw_vers', '-productVersion'], text=True).strip(),
                    'run_id': os.environ.get('GITHUB_RUN_ID'), 'source_commit': os.environ.get('GITHUB_SHA'),
                    'row_count': len(records), 'bounds_seconds': BOUNDS}
        (out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
        lines = ['# macOS qualification', '', '| Row | Verdict | Evidence bound |', '|---|---|---|']
        lines += ['| ' + r['row'] + ' | ' + r['verdict'] + ' | ' + r['evidence'] + ' |' for r in records]
        (out / 'summary.md').write_text('\n'.join(lines) + '\n')
        shutil.rmtree(ROOT)
        cleaned['checks']['fixture_removed'] = not ROOT.exists()
        (out / 'cleanup.json').write_text(json.dumps(cleaned, indent=2) + '\n')
    if interrupted:
        sys.exit(1)


if __name__ == '__main__':
    main()
