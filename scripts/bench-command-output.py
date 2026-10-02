#!/usr/bin/env python3
"""Compare daemon RSS while no-op scripts emit stdout/stderr (Linux only).

Example: python3 scripts/bench-command-output.py --before /path/to/baseline \
    --after target/release/fail2ban-rs --repeats 3

Uses temporary log/state/socket paths, a single runtime worker, and script
commands that only write /dev/zero bytes and sleep. No firewall is changed.
"""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time


def request(path, command):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(40)
        stream.connect(str(path))
        payload = json.dumps(command).encode()
        stream.sendall(struct.pack('<I', len(payload)) + payload)

        def read(size):
            data = bytearray()
            while len(data) < size:
                chunk = stream.recv(size - len(data))
                if not chunk:
                    raise RuntimeError('daemon closed response')
                data.extend(chunk)
            return data

        size = struct.unpack('<I', read(4))[0]
        if size > 16 * 1024 * 1024:
            raise RuntimeError('oversized control response')
        return json.loads(read(size))


def rss_kib(pid):
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        if line.startswith('VmRSS:'):
            return int(line.split()[1])
    raise RuntimeError('process has no VmRSS')


def probe(binary, size_bytes):
    with tempfile.TemporaryDirectory(prefix='f2b-output-bench-') as tmp:
        root = Path(tmp)
        log = root / 'input.log'
        log.touch()
        control = root / 'control' / 'daemon.sock'
        config = root / 'config.toml'
        config.write_text(f'''[global]
state_dir = "{root}/state"
socket_path = "{control}"
[logging]
level = "error"
[jail.probe]
log_path = "{log}"
filter = ['Failed from <HOST>']
ignoreself = false
[jail.probe.backend.script]
ban_cmd = "head -c {size_bytes} /dev/zero; head -c {size_bytes} /dev/zero >&2; sleep 0.2"
unban_cmd = "true"
''')
        env = dict(os.environ, TOKIO_WORKER_THREADS='1')
        with (root / 'daemon.log').open('w+') as stderr:
            proc = subprocess.Popen([str(binary), '-c', str(config), 'run'],
                                    stdout=subprocess.DEVNULL, stderr=stderr, env=env)
            try:
                deadline = time.monotonic() + 10
                while True:
                    if proc.poll() is not None:
                        stderr.seek(0)
                        raise RuntimeError(stderr.read())
                    if control.exists():
                        try:
                            response = request(control, {'cmd': 'status'})
                            if response.get('status') == 'ok':
                                break
                        except (ConnectionRefusedError, FileNotFoundError):
                            pass
                    if time.monotonic() >= deadline:
                        raise TimeoutError('daemon did not become ready')
                    time.sleep(0.01)
                time.sleep(0.3)
                idle = rss_kib(proc.pid)
                peak = idle
                start = time.monotonic()
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(request, control,
                                         {'cmd': 'ban', 'ip': '192.0.2.1', 'jail': 'probe'})
                    while not future.done():
                        peak = max(peak, rss_kib(proc.pid))
                        time.sleep(0.005)
                    response = future.result()
                if response.get('status') != 'ok':
                    raise RuntimeError(f'ban action failed: {response}')
                return {'bytes_per_stream': size_bytes, 'idle_rss_kib': idle,
                        'peak_sampled_rss_kib': peak, 'delta_rss_kib': peak - idle,
                        'elapsed_seconds': time.monotonic() - start,
                        'response': response}
            finally:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', required=True, type=Path)
    parser.add_argument('--after', required=True, type=Path)
    parser.add_argument('--repeats', default=3, type=int)
    parser.add_argument('--sizes-mib', nargs='+', default=[0, 16, 64], type=int)
    args = parser.parse_args()
    if args.repeats < 1 or any(size < 0 for size in args.sizes_mib):
        parser.error('repeats must be positive and sizes nonnegative')
    for size in args.sizes_mib:
        for repeat in range(args.repeats):
            for label, binary in [('before', args.before), ('after', args.after)]:
                result = probe(binary.resolve(), size * 1024 * 1024)
                print(json.dumps(dict(label=label, binary=str(binary.resolve()),
                                      repeat=repeat, **result)), flush=True)


if __name__ == '__main__':
    main()
