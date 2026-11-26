#!/usr/bin/env python3
"""Process-level, no-network fixture beyond loopback. Run after cargo build."""
import http.client
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import time


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def status(port_, path):
    conn = http.client.HTTPConnection("127.0.0.1", port_, timeout=1)
    try:
        conn.request("GET", path)
        r = conn.getresponse()
        r.read()
        return r.status
    finally:
        conn.close()


def until(check):
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.02)
    raise AssertionError("state transition timed out")


def main():
    root = pathlib.Path(__file__).resolve().parents[1]
    exe = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else root / "target/debug/ai-edge-gateway"
    public, management = port(), port()
    while management == public:
        management = port()
    cfg = f'''dns_servers = ["127.0.0.1:53"]
byok_egress = "loop"
[listen]
bind = "127.0.0.1:{public}"
management = "127.0.0.1:{management}"
[limits]
shutdown_drain_timeout_secs = 2
websocket = false
[egress.loop]
mode = "v4_only"
local_v4 = "127.0.0.1"
'''
    test_secret = "smoke-test-credential-must-not-appear"
    with tempfile.TemporaryDirectory(prefix="aieg-smoke-") as dir_:
        dir_ = pathlib.Path(dir_)
        path = dir_ / "config.toml"

        def set_config(text):
            tmp = path.with_suffix(".tmp")
            tmp.write_text(text, encoding="utf-8")
            tmp.chmod(0o600)
            tmp.replace(path)

        def check_config():
            return subprocess.run([exe, "--config", path, "--check"], capture_output=True, text=True, timeout=5)

        set_config(cfg)
        assert check_config().returncode == 0
        set_config(cfg.replace("127.0.0.1\"", "192.0.2.234\""))
        invalid = check_config()
        assert invalid.returncode != 0 and "cannot bind" in invalid.stderr
        set_config(cfg)
        with (dir_ / "log").open("w+") as log:
            p = subprocess.Popen([exe, "--config", path], stdout=log, stderr=log, env={**os.environ, "AIEG_LOG": "on"})
            try:
                until(lambda: status(management, "/healthz") == 200)
                assert status(public, "/openai/v1/models?key=" + test_secret) == 401
                set_config(cfg + f'unknown = "{test_secret}"\n')
                p.send_signal(signal.SIGHUP)
                # This smoke test also works with a compile-time quiet binary.
                time.sleep(0.2)
                assert p.poll() is None and status(public, "/openai/v1/models") == 401
                set_config(cfg + '\n[routes.openai]\nmode = "disabled"\n')
                p.send_signal(signal.SIGHUP)
                until(lambda: status(public, "/openai/v1/models") == 404)
                assert status(public, "/claude/v1/models") == 401
                p.terminate()
                assert p.wait(timeout=5) == 0
                log.seek(0)
                assert test_secret not in log.read()
            finally:
                if p.poll() is None:
                    p.kill()
                    p.wait(timeout=3)
    print("process smoke OK (invalid bind, redaction, atomic SIGHUP, SIGTERM)")


if __name__ == "__main__":
    main()
