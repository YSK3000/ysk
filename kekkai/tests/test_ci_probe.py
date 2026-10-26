"""Run the actual Tor probe shell loop with controlled CLI responses, without networking."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

import _support  # noqa: F401  テスト用の環境変数を設定する副作用のため読み込む


class ProbeExitTest(unittest.TestCase):
    def test_probe_requires_successful_cli_and_nonempty_success_page(self):
        script = (Path(__file__).resolve().parents[1] / 'scripts' / 'ci_probe.sh').read_text()
        loop = script[script.index('OK=0\n'):script.index('\nkill $TOR\n')]
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / 'python'
            fake.write_text('''#!/bin/sh
if [ "$1" = "-m" ]; then
  case "$PROBE_CASE" in
    cli_failure) echo '{"status":200,"text":"page"}'; exit 1 ;;
    http_failure) echo '{"status":503,"text":"service error"}' ;;
    empty_page) echo '{"status":200,"text":""}' ;;
    invalid_json) echo 'not JSON' ;;
    binary) echo '{"status":200,"text":"page","skipped":"binary"}' ;;
    ok) echo '{"status":200,"text":"page"}' ;;
  esac
  exit 0
fi
exec ''' + shlex.quote(sys.executable) + ' "$@"\n')
            fake.chmod(0o755)
            command = ('PY=' + shlex.quote(str(fake)) + '\nONIONS=' + 'a' * 56 + '.onion\n'
                       + loop + '\n[ "$OK" = 1 ]\n')
            for case in ('cli_failure', 'http_failure', 'empty_page', 'invalid_json', 'binary', 'ok'):
                with self.subTest(case=case):
                    env = dict(os.environ, PROBE_CASE=case)
                    result = subprocess.run(['bash', '-c', command], env=env, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode == 0, case == 'ok', result.stdout.decode())
