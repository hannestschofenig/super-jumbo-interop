"""Check Jumbo receive limits and fatal alerts against both TLS servers.

Build both libraries first using run_wolfssl_mbedtls_jumbo_interop.sh.
Override WOLF_BUILD and MBED_BUILD to select other CMake build directories.
"""
import os
import subprocess
import tempfile
import time
from pathlib import Path
root = Path(__file__).resolve().parent.parent
wolf_source = Path(os.environ.get('WOLF_SOURCE_DIR', str(root / 'wolfssl_jumbo'))).resolve()
wolf_build = Path(os.environ.get('WOLF_BUILD', '/tmp/wolfssl_jumbo_build')).resolve()
mbed_build = Path(os.environ.get('MBED_BUILD', '/tmp/mbedtls_jumbo_build')).resolve()
logs = Path(tempfile.mkdtemp(prefix='jumbo-overflow-'))
# CMake supplies the peer built with the same settings as the library.
# Retain standalone use for the existing interoperability script.
if os.environ.get('JUMBO_HELPER'):
    helper = Path(os.environ['JUMBO_HELPER']).resolve()
else:
    helper = logs / 'jumbo-overflow'
    subprocess.run([
        os.environ.get('CC', 'cc'), str(root / 'tests/jumbo_overflow.c'),
        '-DWOLFSSL_MAX_RECORD_SIZE=' + os.environ.get('LIMIT', '65535'),
        '-I' + str(wolf_build), '-I' + str(wolf_source),
        '-L' + str(wolf_build / 'lib'), '-L' + str(wolf_build),
        '-Wl,-rpath,' + str(wolf_build / 'lib'), '-Wl,-rpath,' + str(wolf_build),
        '-lwolfssl', '-o', str(helper),
    ], check=True)
print('Logs:', logs, flush=True)
for library in ['mbed', 'wolf']:
    for case in ['boundary', 'encrypted_overflow', 'prefix', 'short_nonminimal', 'nonminimal', 'oversized', 'huge']:
        port = int(os.environ.get('JUMBO_TEST_PORT', '44550'))
        cmd = [str(helper), 'server', str(port), case] if library == 'wolf' else [
            str(mbed_build / 'programs/ssl/ssl_server2'), 'server_addr=127.0.0.1', f'server_port={port}',
            'force_version=tls13', 'auth_mode=none', 'debug_level=2', 'tickets=0',
            'jumbo_record_size_limit=128', 'raw_payload_size=127', 'exchanges=1']
        log = logs / f'{library}-{case}.log'
        with log.open('w') as out:
            proc = subprocess.Popen(cmd, cwd=wolf_source, stdout=out, stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    if proc.poll() is not None: raise RuntimeError(log.read_text())
                    if 'READY' in log.read_text() or 'Waiting for a remote connection' in log.read_text(): break
                    time.sleep(.05)
                else: raise RuntimeError('server startup timeout')
                cli = subprocess.run([str(helper), 'client', str(port), case], capture_output=True, text=True, timeout=8)
                if cli.returncode: raise RuntimeError(cli.stdout + cli.stderr + '\n' + log.read_text()[-4000:])
                print(library, cli.stdout.strip(), flush=True)
                if library == 'wolf':
                    if proc.wait(timeout=5): raise RuntimeError(log.read_text())
            finally:
                if proc.poll() is None: proc.terminate()
                try: proc.wait(timeout=3)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
