/* Regression peer: deliberately violates negotiated record limits. */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed line %d: %s\n", __LINE__, #x); return 1; } } while (0)

int main(int argc, char** argv)
{
    int server, fd, peer, n, port, good;
    struct sockaddr_in addr;
    struct timeval timeout = { 4, 0 };
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_ALERT_HISTORY history;
    unsigned char buf[512];
    const unsigned char prefix[] = {23, 0xc0};
    const unsigned char nonminimal[] = {23, 0x80, 0, 0, 64};
    const unsigned char short_nonminimal[] = {23, 0x40, 1};
    const unsigned char oversized[] = {23, 0x40, 145};
    const unsigned char huge[] = {23, 0x80, 1, 0, 0};
    const unsigned char *header = NULL;
    size_t size = 0;
    CHECK(argc == 4);
    server = strcmp(argv[1], "server") == 0;
    port = atoi(argv[2]);
    good = strcmp(argv[3], "boundary") == 0;
    wolfSSL_Init();
    ctx = wolfSSL_CTX_new(server ? wolfTLSv1_3_server_method() : wolfTLSv1_3_client_method());
    CHECK(ctx != NULL);
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    CHECK(wolfSSL_CTX_UseLargeRecordSizeLimit(ctx, server ? 128 : 4096) == WOLFSSL_SUCCESS);
    if (server) {
        CHECK(wolfSSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM) == WOLFSSL_SUCCESS);
        CHECK(wolfSSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM) == WOLFSSL_SUCCESS);
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (server) {
        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        CHECK(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
        CHECK(listen(fd, 1) == 0);
        puts("READY"); fflush(stdout);
        peer = accept(fd, NULL, NULL);
        CHECK(peer >= 0);
    } else {
        CHECK(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
        peer = fd;
    }
    setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ssl = wolfSSL_new(ctx);
    CHECK(ssl != NULL);
    CHECK(wolfSSL_set_fd(ssl, peer) == WOLFSSL_SUCCESS);
    CHECK((server ? wolfSSL_accept(ssl) : wolfSSL_connect(ssl)) == WOLFSSL_SUCCESS);
    if (!server) {
        CHECK(ssl->options.largeRecordSz);
        if (good || strcmp(argv[3], "encrypted_overflow") == 0) {
            /* Bypass the sender's limit to exercise receiver enforcement. */
            ssl->largeRecordSizeLimitPeer = 4096;
            memset(buf, 'A', sizeof(buf));
            n = good ? 127 : 128;
            CHECK(wolfSSL_write(ssl, buf, n) == n);
        } else {
            if (strcmp(argv[3], "prefix") == 0) { header = prefix; size = sizeof(prefix); }
            if (strcmp(argv[3], "nonminimal") == 0) { header = nonminimal; size = sizeof(nonminimal); }
            if (strcmp(argv[3], "short_nonminimal") == 0) { header = short_nonminimal; size = sizeof(short_nonminimal); }
            if (strcmp(argv[3], "oversized") == 0) { header = oversized; size = sizeof(oversized); }
            if (strcmp(argv[3], "huge") == 0) { header = huge; size = sizeof(huge); }
            CHECK(header != NULL);
            /* Header only: receiver must reject without waiting for payload. */
            CHECK(send(peer, header, size, 0) == (int)size);
        }
    }
    n = wolfSSL_read(ssl, buf, sizeof(buf));
    memset(&history, 0, sizeof(history));
    wolfSSL_get_alert_history(ssl, &history);
    if (good) {
        CHECK(server ? n == 127 : n > 0);
        if (server) CHECK(wolfSSL_write(ssl, "OK", 2) == 2);
    } else {
        CHECK(n <= 0);
        CHECK((server ? history.last_tx.code : history.last_rx.code) == 22);
        CHECK((server ? history.last_tx.level : history.last_rx.level) == 2);
    }
    printf("PASS %s %s\n", argv[1], argv[3]);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    close(peer);
    if (server) close(fd);
    wolfSSL_Cleanup();
    return 0;
}
