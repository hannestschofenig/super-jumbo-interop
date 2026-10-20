# Super Jumbo TLS Interoperability Tests

This repository builds experimental Super Jumbo Record Size Limit implementations
in wolfSSL and Mbed TLS and tests their handling of receive limits and malformed
record lengths. CMake builds the libraries separately using `ExternalProject_Add()`,
compiles a test peer, and registers the Python test runner with CTest.

## Specification and Implementations

The implementations target
[draft-ietf-tls-super-jumbo-record-limit-03](https://datatracker.ietf.org/doc/html/draft-ietf-tls-super-jumbo-record-limit-03)
for TLS 1.3 over TCP. Each endpoint advertises its own receive limit in a fixed
four-byte `uint32` extension value. The limit covers `TLSInnerPlaintext`, including
content type and padding, and excludes AEAD expansion.

After negotiation, application-traffic records use `TLSLargeCiphertext` with
canonical variable-length record lengths. Oversized TLS records and invalid Jumbo
length encodings require a fatal `record_overflow` alert (22).

- [wolfSSL implementation, branch super_jumbo](https://github.com/hannestschofenig/wolfssl/tree/super_jumbo)
- [wolfSSL README_JUMBO.md](https://github.com/hannestschofenig/wolfssl/blob/super_jumbo/README_JUMBO.md)
- [Mbed TLS implementation, branch jumbo](https://github.com/hannestschofenig/mbedtls/tree/jumbo)
- [Mbed TLS README_Jumbo.md](https://github.com/hannestschofenig/mbedtls/blob/jumbo/README_Jumbo.md)

Passing these tests establishes the specific behaviors described below; it does
not establish full draft conformance.

## Directory Layout

```text
.
|-- CMakeLists.txt
|-- README.md
|-- wolfssl_jumbo/                 # Implementation checkout
|-- mbedtls_jumbo/                 # Implementation checkout
|-- tests/
|   |-- jumbo_overflow.c           # Test peer and malformed-record generator
|   `-- run_jumbo_overflow_tests.py
`-- run_wolfssl_mbedtls_jumbo_interop.sh
```

Both regression test files belong to this repository's `tests/` directory.
The C peer uses wolfSSL internals to deliberately bypass sender checks when
exercising receiver enforcement.

## Requirements

- A POSIX environment with localhost TCP sockets; tested on Linux.
- A C compiler with C99 support, CMake 3.20 or later, and Make or Ninja.
- Python 3; the runner uses only the standard library.
- Both modified implementation checkouts, with their required submodules,
  test certificates, and implementation-specific build dependencies.
- Permission to bind and connect to `127.0.0.1`; port 44550 must be available
  unless another port is configured.

## Obtain the Implementations

From this repository's root, if the directories are not already present:

```sh
git clone --recurse-submodules --branch super_jumbo \
  https://github.com/hannestschofenig/wolfssl.git wolfssl_jumbo
git clone --recurse-submodules --branch jumbo \
  https://github.com/hannestschofenig/mbedtls.git mbedtls_jumbo
```

CMake uses local source trees and does not clone or update them. Pin or record
both implementation commits for reproducible results. The parent repository can
also manage these checkouts as Git submodules.

## Build and Test

Run from this repository's root:

```sh
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Debug \
  -DJUMBO_MAX_RECORD_SIZE=65535
cmake --build build -j4
ctest --test-dir build --output-on-failure
```

Build before running CTest: CTest does not compile the programs. The build creates
the shared wolfSSL library, Mbed TLS `ssl_server2` and `ssl_client2`, and the
`jumbo_overflow` peer. The peer and wolfSSL share the same record-size definition.
Implementation builds are isolated in `build/wolfssl` and `build/mbedtls`.

For individual scenario results and the log directory:

```sh
ctest --test-dir build -V
```

CTest reports one test, `jumbo_overflow`, containing 14 scenario runs. A successful
run ends with `100% tests passed, 0 tests failed out of 1`. The runner prints a
temporary log directory containing a server log for each scenario. Logs remain
available after the run.

## Test Coverage

A wolfSSL client exercises both an Mbed TLS server and a wolfSSL server. Each
server advertises a 128-byte receive limit, while the client advertises 4096 bytes,
checking that the receiver's own limit is enforced. Seven scenarios run against
each server:

| Scenario | Expected behavior |
| --- | --- |
| `boundary` | Accept 127 application bytes plus the inner content-type byte, exactly reaching the receive limit. |
| `encrypted_overflow` | Reject an encrypted record one byte over the inner-plaintext limit. |
| `prefix` | Reject the reserved varuint prefix `11`. |
| `short_nonminimal` | Reject a two-byte encoding of a value that fits in one byte. |
| `nonminimal` | Reject a four-byte encoding of a value that fits in two bytes. |
| `oversized` | Reject an oversized ciphertext header without waiting for its payload. |
| `huge` | Reject a header advertising 65536 ciphertext bytes without waiting for its payload. |

Every rejection must produce a fatal `record_overflow` alert observed by the
client. Socket and process timeouts catch receivers that wait for missing data.
`JUMBO_MAX_RECORD_SIZE` controls wolfSSL build capacity; these scenarios retain
their 128-byte advertised server receive limit.

The suite does not cover DTLS, 0-RTT, resumption, KeyUpdate, or the full draft size
range. The separate `run_wolfssl_mbedtls_jumbo_interop.sh` script exercises normal
50000-byte transfers in both client/server combinations. CTest does not run that
script automatically.

## Configuration

| CMake option | Default | Purpose |
| --- | --- | --- |
| `JUMBO_MAX_RECORD_SIZE` | `65535` | wolfSSL capacity; the test project accepts 4096 through 65535. |
| `JUMBO_WOLFSSL_SOURCE_DIR` | `<repo>/wolfssl_jumbo` | wolfSSL source checkout. |
| `JUMBO_MBEDTLS_SOURCE_DIR` | `<repo>/mbedtls_jumbo` | Mbed TLS source checkout. |
| `JUMBO_TEST_PORT` | `44550` | Local TCP port, from 1024 through 65535. |
| `BUILD_TESTING` | `ON` | Register the regression test with CTest. |

Example with alternate checkouts and a different port:

```sh
cmake -S . -B build \
  -DJUMBO_WOLFSSL_SOURCE_DIR=/path/to/wolfssl \
  -DJUMBO_MBEDTLS_SOURCE_DIR=/path/to/mbedtls \
  -DJUMBO_TEST_PORT=44551
cmake --build build -j4
ctest --test-dir build --output-on-failure
```

To run Python directly against the CMake-built programs:

```sh
JUMBO_HELPER="$PWD/build/jumbo_overflow" \
WOLF_BUILD="$PWD/build/wolfssl" \
MBED_BUILD="$PWD/build/mbedtls" \
python3 tests/run_jumbo_overflow_tests.py
```

Set `WOLF_SOURCE_DIR` as well for a non-default wolfSSL source tree; the runner
uses that checkout's test certificates. Set `JUMBO_TEST_PORT` to change the port
when running Python directly. CTest supplies these settings automatically.
