"""Shared by the tests."""
import time

from pqcsuite import tls

try:
    tls.lib()
    REASON = None  # why the tests that need OpenSSL 3.5 are skipped, when they are
except tls.OpenSSLUnavailable as e:
    REASON = str(e)


def wait(check, seconds=5.0):
    """Poll `check` until it is true or `seconds` pass; its last answer."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(0.05)
    return check()


def redis_application(test, server_namespace, client_namespace, host, source=None):
    """A real Redis process and independent RESP client inside the VPN namespaces."""
    import shutil
    import subprocess
    import sys
    if not shutil.which("redis-server"):
        test.fail("real VPN application checks require redis-server")
    server = subprocess.Popen(["ip", "netns", "exec", server_namespace, "redis-server", "--bind", host,
                               "--port", "6379", "--save", "", "--appendonly", "no", "--protected-mode", "no"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    def stop():
        server.terminate()
        try:
            server.wait(5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
    test.addCleanup(stop)
    code = r"""
import socket, sys
with socket.socket() as s:
 s.settimeout(3)
 if sys.argv[2]: s.bind((sys.argv[2], 0))
 s.connect((sys.argv[1], 6379))
 f = s.makefile('rb')
 s.sendall(b'*3\r\n$3\r\nSET\r\n$5\r\nprobe\r\n$12\r\nreal-redis\xc3\xa9\r\n')
 assert f.readline() == b'+OK\r\n'
 s.sendall(b'*2\r\n$3\r\nGET\r\n$5\r\nprobe\r\n')
 assert f.readline() == b'$12\r\n'
 assert f.read(14) == b'real-redis\xc3\xa9\r\n'
"""
    def request():
        return subprocess.run(["ip", "netns", "exec", client_namespace, sys.executable, "-c", code, host, source or ""],
                              capture_output=True, timeout=5).returncode == 0
    return request
