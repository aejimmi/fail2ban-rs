#!/usr/bin/env python3
"""Compare Linux daemon RSS under continuous unique-IP failures, without firewall changes.

Example: python3 scripts/bench-tracker-cleanup.py --before /path/old --after /path/new
RSS includes allocator high-water retention; this is not a fixed-memory guarantee.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time


def request(path):
    def receive(sock, size):
        data = bytearray()
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise RuntimeError("daemon socket closed")
            data.extend(chunk)
        return data

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(str(path))
        body = b'{"cmd":"stats"}'
        sock.sendall(struct.pack("<I", len(body)) + body)
        size = struct.unpack("<I", receive(sock, 4))[0]
        if size > 1024 * 1024:
            raise RuntimeError("unexpectedly large daemon response")
        result = json.loads(receive(sock, size))
        if result.get("status") != "ok":
            raise RuntimeError(result)
        return result["data"]


def sample(case, sent, elapsed):
    usage = {}
    for line in Path(f'/proc/{case["process"].pid}/status').read_text().splitlines():
        key, _, value = line.partition(":")
        if key in ("VmRSS", "VmHWM", "Threads"):
            usage[key] = value.strip()
    return {"elapsed_seconds": round(elapsed, 3), "sent_failures": sent,
            "usage": usage, "stats": request(case["socket"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=70)
    parser.add_argument("--rate", type=int, default=1000)
    args = parser.parse_args()
    if args.seconds < 65 or args.rate <= 0:
        parser.error("--seconds must be >=65 and --rate must be positive")
    cases = []
    with tempfile.TemporaryDirectory(prefix="f2b-cleanup-") as directory:
        try:
            for name, binary in (("before", args.before), ("after", args.after)):
                root = Path(directory) / name
                root.mkdir()
                log = root / "input.log"
                log.touch()
                control = root / "control" / "daemon.sock"
                config = root / "config.toml"
                config.write_text(f'''[global]
state_dir = "{root}/state"
socket_path = "{control}"
[logging]
level = "error"
[jail.probe]
log_path = "{log}"
date_format = "epoch"
filter = ['Failed from <HOST>']
max_retry = 2
find_time = "1s"
ban_time = "1h"
ignoreself = false
[jail.probe.backend.script]
ban_cmd = "true"
unban_cmd = "true"
''')
                stderr = (root / "stderr.log").open("w")
                process = subprocess.Popen([str(binary.resolve()), "-c", str(config), "run"],
                                           stdout=subprocess.DEVNULL, stderr=stderr,
                                           env={**os.environ, "TOKIO_WORKER_THREADS": "1"})
                case = {"name": name, "process": process, "socket": control,
                        "log": log, "stderr": stderr, "samples": []}
                cases.append(case)
                deadline = time.monotonic() + 15
                while not control.exists():
                    if process.poll() is not None:
                        raise RuntimeError(f'{name} daemon exited: {(root / "stderr.log").read_text()}')
                    if time.monotonic() > deadline:
                        raise TimeoutError(f"{name} daemon startup")
                    time.sleep(0.01)
            # Ensure both file watchers have opened their empty files at EOF.
            time.sleep(0.5)
            for case in cases:
                case["samples"].append(sample(case, 0, 0))
            start = time.monotonic()
            sent = 0
            for second in range(1, args.seconds + 1):
                timestamp = int(time.time())
                lines = "".join(f'{timestamp} Failed from {ipaddress.IPv4Address(0x0A000000 + index)}\n'
                                for index in range(sent, sent + args.rate))
                for case in cases:
                    with case["log"].open("a") as output:
                        output.write(lines)
                sent += args.rate
                time.sleep(max(0, start + second - time.monotonic()))
                if second in (30, 59, 61, args.seconds):
                    for case in cases:
                        point = sample(case, sent, time.monotonic() - start)
                        case["samples"].append(point)
                        print(json.dumps({"name": case["name"], **point}), flush=True)
            for case in cases:
                stats = request(case["socket"])
                if stats["total_failures"] != sent or stats["active_bans"] != 0:
                    raise RuntimeError(f'{case["name"]}: incomplete replay or unexpected bans: {stats}')
            print(json.dumps({"rate": args.rate, "seconds": args.seconds,
                              "results": {case["name"]: case["samples"] for case in cases}}, indent=2))
        finally:
            for case in cases:
                process = case["process"]
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                case["stderr"].close()


if __name__ == "__main__":
    main()
