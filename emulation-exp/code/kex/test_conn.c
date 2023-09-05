/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <time.h>
#include <string.h>
#define MASTER_SECRET_LABEL "CLIENT_RANDOM"
#define CLIENT_EARLY_LABEL "CLIENT_EARLY_TRAFFIC_SECRET"
#define CLIENT_HANDSHAKE_LABEL "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
#define SERVER_HANDSHAKE_LABEL "SERVER_HANDSHAKE_TRAFFIC_SECRET"
#define CLIENT_APPLICATION_LABEL "CLIENT_TRAFFIC_SECRET_0"
#define SERVER_APPLICATION_LABEL "SERVER_TRAFFIC_SECRET_0"
#define EARLY_EXPORTER_SECRET_LABEL "EARLY_EXPORTER_SECRET"
#define EXPORTER_SECRET_LABEL "EXPORTER_SECRET"

#define NS_IN_MS 1000000.0
#define MS_IN_S 1000

const char* host = "192.168.1.128:4433";

SSL* do_tls_handshake(SSL_CTX* ssl_ctx)
{
    BIO* conn;
    SSL* ssl;
    int ret;

    conn = BIO_new(BIO_s_connect());
    if (!conn)
    {
        return 0;
    }

    BIO_set_conn_hostname(conn, host);
    BIO_set_conn_mode(conn, BIO_SOCK_NODELAY);

    ssl = SSL_new(ssl_ctx);

    SSL_set_bio(ssl, conn, conn);

    /* ok, lets connect */
    ret = SSL_connect(ssl);
    if (ret <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return 0;
    }

#if defined(SOL_SOCKET) && defined(SO_LINGER)
    {
        struct linger no_linger = {.l_onoff = 1, .l_linger = 0};
        int fd = SSL_get_fd(ssl);
        if (fd >= 0)
        {
            (void)setsockopt(fd, SOL_SOCKET, SO_LINGER, (char*)&no_linger,
                             sizeof(no_linger));
        }
    }
#endif
    return ssl;
}

// "/home/zzd/mytest.log"
static char g_NAME_LOGFILE[100]; 

void my_keylog_callback(const SSL *ssl, const char *line) {
    FILE *keylog_file = fopen(g_NAME_LOGFILE, "a");
    if (keylog_file) {
        fputs(line, keylog_file);
        fprintf(keylog_file, "\n");
        fclose(keylog_file);
    }
}

int main(int argc, char* argv[])
{
    int ret = -1;
    SSL_CTX* ssl_ctx = 0;
    if(argc != 3)
    {
        fprintf(stderr, "Wrong number of arguments.\n");
        goto end;
    }
    const char* kex_alg = argv[1];
    strcpy(g_NAME_LOGFILE, argv[2]);

    const char* ciphersuites = "TLS_AES_256_GCM_SHA384";
    const SSL_METHOD* ssl_meth = TLS_client_method();
    SSL* ssl = NULL;

    ssl_ctx = SSL_CTX_new(ssl_meth);
    if (!ssl_ctx)
    {
        goto ossl_error;
    }
    SSL_CTX_set_keylog_callback(ssl_ctx, my_keylog_callback); /* 设置日志回调 */

    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_quiet_shutdown(ssl_ctx, 1);

    ret = SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    if (ret != 1)
    {
        goto ossl_error;
    }

    ret = SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
    if (ret != 1)
    {
        goto ossl_error;
    }

    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_COMPRESSION);

    ret = SSL_CTX_set_ciphersuites(ssl_ctx, ciphersuites);
    if (ret != 1)
    {
        goto ossl_error;
    }
    ret = SSL_CTX_set1_groups_list(ssl_ctx, kex_alg);
    if (ret != 1)
    {
        goto ossl_error;
    }

    ret = SSL_CTX_load_verify_locations(ssl_ctx, "../tmp/nginx/conf/CA.crt", 0);
    if(ret != 1)
    {
        goto ossl_error;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

        ssl = do_tls_handshake(ssl_ctx);
        if (!ssl)
        {
            /* Retry since at high packet loss rates,
             * the connect() syscall fails sometimes.
             * Non-retryable errors are caught by manual
             * inspection of logs, which has sufficed
             * for our purposes */
            //continue;
	    printf("connection failed**\n");
        }
        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        ret = BIO_closesocket(SSL_get_fd(ssl));
        if(ret == -1)
        {
            goto ossl_error;
        }

        SSL_free(ssl);

    ret = 0;
    goto end;

ossl_error:
    fprintf(stderr, "Unrecoverable OpenSSL error.\n");
    ERR_print_errors_fp(stderr);
end:
    SSL_CTX_free(ssl_ctx);
    return ret;
}
