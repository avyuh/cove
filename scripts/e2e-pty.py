#!/usr/bin/env python3
import errno
import fcntl
import os
import pty
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import select


COVE = os.environ.get("COVE_BIN", "/usr/local/bin/cove")
FLAG_MASK = termios.ECHO | termios.ICANON | termios.ISIG | termios.IEXTEN


class PtyRun:
    def __init__(self, argv, rows=24, cols=80):
        self.master, self.slave = pty.openpty()
        set_winsize(self.slave, rows, cols)
        self.before = termios.tcgetattr(self.slave)
        self.output = b""
        pid = os.fork()
        if pid == 0:
            try:
                os.setsid()
                fcntl.ioctl(self.slave, termios.TIOCSCTTY, 0)
                os.dup2(self.slave, 0)
                os.dup2(self.slave, 1)
                os.dup2(self.slave, 2)
                if self.slave > 2:
                    os.close(self.slave)
                os.close(self.master)
                os.execvpe(argv[0], argv, os.environ.copy())
            except BaseException as exc:
                os.write(2, f"pty exec failed: {exc}\n".encode())
                os._exit(127)
        self.pid = pid

    def read_until(self, pattern, timeout=20):
        deadline = time.time() + timeout
        rx = re.compile(pattern)
        while time.time() < deadline:
            if rx.search(self.text()):
                return self.text()
            r, _, _ = select.select([self.master], [], [], 0.05)
            if not r:
                continue
            try:
                chunk = os.read(self.master, 4096)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            self.output += chunk
        raise AssertionError(f"timed out waiting for {pattern!r}; output:\n{self.text()}")

    def write(self, data):
        os.write(self.master, data)

    def resize(self, rows, cols):
        set_winsize(self.master, rows, cols)
        os.kill(self.pid, signal.SIGWINCH)

    def wait(self, timeout=20):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                pid, status = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                return 0
            if pid == self.pid:
                self._drain()
                if os.WIFEXITED(status):
                    return os.WEXITSTATUS(status)
                if os.WIFSIGNALED(status):
                    return 128 + os.WTERMSIG(status)
                return 1
            time.sleep(0.05)
        os.kill(self.pid, signal.SIGKILL)
        os.waitpid(self.pid, 0)
        raise AssertionError(f"process timed out; output:\n{self.text()}")

    def restored(self):
        after = termios.tcgetattr(self.slave)
        return (self.before[3] & FLAG_MASK) == (after[3] & FLAG_MASK)

    def close(self):
        os.close(self.master)
        os.close(self.slave)

    def text(self):
        return self.output.decode("utf-8", "replace")

    def _drain(self):
        end = time.time() + 0.25
        while time.time() < end:
            r, _, _ = select.select([self.master], [], [], 0.02)
            if not r:
                continue
            try:
                chunk = os.read(self.master, 4096)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    return
                raise
            if not chunk:
                return
            self.output += chunk


def set_winsize(fd, rows, cols):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_exit(argv, env=None):
    res = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    return res.returncode, res.stdout.decode("utf-8", "replace"), res.stderr.decode("utf-8", "replace")


def test_resize():
    script = 'stty size; while IFS= read -r _; do sz="$(stty size)"; echo "$sz"; [ "$sz" = "33 100" ] && exit 0; done; exit 1'
    run = PtyRun([COVE, "--", "/bin/bash", "-lc", script], 24, 80)
    try:
        run.read_until(r"(^|\n|\r)24 80(\r|\n)")
        saw_resize = False
        last_error = None
        for settle in (0.05, 0.10, 0.20, 0.40, 0.80):
            run.resize(33, 100)
            time.sleep(settle)
            run.write(b"\n")
            try:
                run.read_until(r"(^|\n|\r)33 100(\r|\n)", timeout=2 + settle)
                saw_resize = True
                break
            except AssertionError as exc:
                last_error = exc
        require(saw_resize, f"resize was not observed after retries: {last_error}")
        rc = run.wait()
        require(rc == 0, f"resize command rc={rc}; output:\n{run.text()}")
        require(run.restored(), "termios was not restored after normal pty exit")
        print("resize_before=24 80")
        print("resize_after=33 100")
        print("termios_normal=restored")
    finally:
        run.close()


def test_ctrl_c():
    script = 'trap "echo GOTINT; exit 130" INT; echo READY; while :; do sleep 10; done'
    run = PtyRun([COVE, "--", "/bin/bash", "-lc", script], 24, 80)
    try:
        run.read_until(r"READY")
        run.write(b"\x03")
        run.read_until(r"GOTINT")
        rc = run.wait()
        require(rc == 130, f"Ctrl-C rc={rc}, want 130; output:\n{run.text()}")
        require(run.restored(), "termios was not restored after Ctrl-C")
        print("ctrl_c=agent-handled rc=130")
        print("termios_interrupt=restored")
    finally:
        run.close()


def test_exit_table():
    table = []
    for want in (0, 42, 70):
        rc, _, err = run_exit([COVE, "--", "/bin/sh", "-c", f"exit {want}"])
        require(rc == want, f"exit {want} got {rc}; stderr={err}")
        table.append((f"exit-{want}", want, rc))

    rc, _, err = run_exit([COVE, "--", "/bin/sh", "-c", "kill -TERM $$; sleep 1"])
    require(rc == 143, f"signal TERM got {rc}; stderr={err}")
    table.append(("signal-TERM", 143, rc))

    rc, _, err = run_exit([COVE, "--", "nonesuch-binary-cove-test"])
    require(rc == 127, f"missing agent got {rc}; stderr={err}")
    table.append(("missing-agent", 127, rc))

    cfg_home = tempfile.mkdtemp(prefix="cove-badcfg.")
    try:
        cfg_dir = os.path.join(cfg_home, "cove")
        os.makedirs(cfg_dir, exist_ok=True)
        ca = os.environ.get("COVE_CA_PEM", os.path.expanduser("~/.config/cove/ca.pem"))
        shutil.copyfile(ca, os.path.join(cfg_dir, "ca.pem"))
        with open(os.path.join(cfg_dir, "config.toml"), "w", encoding="utf-8") as f:
            f.write('[options]\ntmp_size = "not-a-size"\nproxy_port = 8080\naudit = false\nallow = []\n')
        env = os.environ.copy()
        env["XDG_CONFIG_HOME"] = cfg_home
        rc, _, err = run_exit([COVE, "--", "/bin/true"], env=env)
        require(rc == 75, f"box setup failure got {rc}; stderr={err}")
        table.append(("box-setup-fail", 75, rc))
    finally:
        shutil.rmtree(cfg_home, ignore_errors=True)

    rc, out, err = run_exit(["/bin/sh", "-c", f"{shell_quote(COVE)} -- /bin/sh -c 'echo hi' | cat"])
    require(rc == 0 and out.strip() == "hi", f"non-tty pipe rc={rc} out={out!r} err={err!r}")
    table.append(("non-tty-pipe", 0, rc))

    print("exit_code_table:")
    for name, want, got in table:
        print(f"  {name} want={want} got={got}")


def shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def main():
    test_resize()
    test_ctrl_c()
    test_exit_table()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        sys.exit(1)
