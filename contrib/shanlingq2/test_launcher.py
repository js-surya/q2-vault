"""The card launcher (launcher.sh, installed as .vault/run) under the host's sh, with a fake app.
Adapted from q2-tailscale's (same author, MIT).

    python3 -m pytest contrib/shanlingq2/test_launcher.py
"""
import os
import pathlib
import subprocess
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent
LAUNCHER = HERE / 'launcher.sh'


@pytest.fixture
def card(tmp_path):
    """A card folder .vault with the launcher as run and a fake app, and a /tmp of its own."""
    d = tmp_path / '.vault'
    d.mkdir()
    (d / 'run').write_text(LAUNCHER.read_text())
    tmp = tmp_path / 'tmp'
    tmp.mkdir()
    return d, tmp


def fake_app(d, body):
    """The app: a shell script; its runs are counted in runs.txt beside it."""
    app = d / 'q2-vault'
    app.write_text('#!/bin/sh\necho run >> "$(dirname "$0")/runs.txt"\n' + body)
    app.chmod(0o755)


def start(d, tmp):
    env = dict(os.environ, Q2VAULT_TMP=str(tmp))
    t0 = time.time()
    subprocess.run(['/bin/sh', str(d / 'run')], env=env, check=True, timeout=5)
    return time.time() - t0


def wait(cond, secs=5):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def pid(tmp):
    return int((tmp / 'q2-vault').read_text())


def alive(p):
    try:
        os.kill(p, 0)
        return True
    except OSError:
        return False


def runs(d):
    f = d / 'runs.txt'
    return len(f.read_text().splitlines()) if f.exists() else 0


def test_start_returns_at_once_and_second_start_is_noop(card):
    d, tmp = card
    fake_app(d, 'trap "exit 0" TERM\nwhile :; do sleep 1; done\n')
    assert start(d, tmp) < 1
    assert wait(lambda: runs(d) == 1)
    first = pid(tmp)
    assert not (tmp / 'q2-vault.want').exists()
    start(d, tmp)
    time.sleep(0.5)
    assert pid(tmp) == first and runs(d) == 1
    assert (tmp / 'q2-vault.want').exists()  # the running Vault is told it's wanted
    os.kill(first, 15)
    assert wait(lambda: not (tmp / 'q2-vault').exists())
    assert not (tmp / 'q2-vault.want').exists()


def test_term_stops_within_3s_and_removes_pid(card):
    d, tmp = card
    fake_app(d, 'trap "" TERM\nwhile :; do sleep 1; done\n')  # an app that ignores TERM: killed after 2 s
    start(d, tmp)
    assert wait(lambda: runs(d) == 1)
    p = pid(tmp)
    t0 = time.time()
    os.kill(p, 15)
    assert wait(lambda: not alive(p) and not (tmp / 'q2-vault').exists(), 4)
    assert time.time() - t0 < 3
    assert not (tmp / 'q2-vault.err').exists()  # nothing of a stopped app left in RAM


def test_crash_restarts_with_backoff_and_logs(card):
    d, tmp = card
    fake_app(d, 'echo boom >&2\nexit 3\n')
    start(d, tmp)
    assert wait(lambda: runs(d) == 1)
    time.sleep(1)
    assert runs(d) == 1  # waits 5 s before the second run
    assert (tmp / 'q2-vault.crash').read_text() == 'boom\nexit 3\n'
    os.kill(pid(tmp), 15)
    assert wait(lambda: not (tmp / 'q2-vault').exists())
    # the next start puts the kept crash in the card's log
    fake_app(d, 'exit 0\n')
    start(d, tmp)
    assert wait(lambda: not (tmp / 'q2-vault').exists())
    assert 'boom' in (d / 'log.txt').read_text()


def test_exit_0_ends_loop(card):
    d, tmp = card
    fake_app(d, 'exit 0\n')
    start(d, tmp)
    assert wait(lambda: not (tmp / 'q2-vault').exists())
    time.sleep(0.5)
    assert runs(d) == 1


def test_runs_from_the_card_with_its_folder(card):
    d, tmp = card
    fake_app(d, 'echo "$@" > "$(dirname "$0")/args.txt"\nexit 0\n')
    start(d, tmp)
    assert wait(lambda: (d / 'args.txt').exists())
    assert (d / 'args.txt').read_text().split() == ['-dir', str(d)]
    assert not list(tmp.glob('*.bin'))  # not copied to /tmp: the Q2's /tmp is RAM


def test_log_is_capped(card):
    d, tmp = card
    (d / 'log.txt').write_text('x' * (300 << 10))
    (tmp / 'q2-vault.crash').write_text('boom\nexit 1\n')
    fake_app(d, 'exit 0\n')
    start(d, tmp)
    assert wait(lambda: not (tmp / 'q2-vault').exists())
    log = (d / 'log.txt').read_text()
    assert len(log) <= (256 << 10) and log.endswith('boom\nexit 1\n')


def test_backoff_doubles_to_a_minute():
    """The loop's delays, from its own lines: 5, 10, 20, 40, then 60 s, never more."""
    lines = [l.strip() for l in LAUNCHER.read_text().splitlines()]
    i = lines.index('delay=$((delay * 2))')
    script = 'delay=5\nfor n in 1 2 3 4 5 6; do echo $delay\n' + '\n'.join(lines[i:i + 2]) + '\ndone\n'
    out = subprocess.run(['/bin/sh', '-c', script], capture_output=True, text=True, check=True).stdout
    assert out.split() == ['5', '10', '20', '40', '60', '60']
