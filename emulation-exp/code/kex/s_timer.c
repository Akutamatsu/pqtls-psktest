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
#include <oqs/oqs.h>

#define NS_IN_MS 1000000.0
#define MS_IN_S 1000

#define TEST_PSK
//const char* host = "192.168.1.128:4433";
const char* host = "10.0.0.1:4433";

static int c_debug = 0;
static BIO *bio_c_out = NULL;
static BIO *bio_err = NULL;

const char *psk_key = "8e8fb9cf7fab49b9fb2ba92ca4b9e217196d9a37917ca7a786347ee19a1efc70";
const char *psk_identity = "zzdtest";

static unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
                                  unsigned int max_identity_len,
                                  unsigned char *psk,
                                  unsigned int max_psk_len)
{
    int ret;
    long key_len;
    unsigned char *key;

    if (c_debug)
        BIO_printf(bio_c_out, "psk_client_cb\n");
    if (!hint) {
        /* no ServerKeyExchange message */
        if (c_debug)
            BIO_printf(bio_c_out,
                       "NULL received PSK identity hint, continuing anyway\n");
    } else if (c_debug) {
        BIO_printf(bio_c_out, "Received PSK identity hint '%s'\n", hint);
    }

    /*
     * lookup PSK identity and PSK key based on the given identity hint here
     */
    ret = BIO_snprintf(identity, max_identity_len, "%s", psk_identity);
    if (ret < 0 || (unsigned int)ret > max_identity_len)
        goto out_err;
    if (c_debug)
        BIO_printf(bio_c_out, "created identity '%s' len=%d\n", identity,
                   ret);

    /* convert the PSK key to binary */
    key = OPENSSL_hexstr2buf(psk_key, &key_len);
    if (key == NULL) {
        BIO_printf(bio_err, "Could not convert PSK key '%s' to buffer\n",
                   psk_key);
        return 0;
    }
    if (max_psk_len > INT_MAX || key_len > (long)max_psk_len) {
        BIO_printf(bio_err,
                   "psk buffer of callback is too small (%d) for key (%ld)\n",
                   max_psk_len, key_len);
        OPENSSL_free(key);
        return 0;
    }

    memcpy(psk, key, key_len);
    OPENSSL_free(key);

    if (c_debug)
        BIO_printf(bio_c_out, "created PSK len=%ld\n", key_len);

    return key_len;
 out_err:
    if (c_debug)
        BIO_printf(bio_err, "Error in PSK client callback\n");
    return 0;
}

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
    const size_t measurements_to_make = strtol(argv[2], 0, 10);
    size_t measurements = 0;

    //const char* ciphersuites = "TLS_AES_256_GCM_SHA384";
    const char* ciphersuites = "TLS_AES_128_GCM_SHA256";
    const SSL_METHOD* ssl_meth = TLS_client_method();
    SSL* ssl = NULL;

    struct timespec start, finish;
    double* handshake_times_ms = malloc(measurements_to_make * sizeof(*handshake_times_ms));
	uint8_t entropy_input[48];
    
	for (size_t i = 0; i < 48; i++) {
		entropy_input[i] = i;
	}

	ret = OQS_randombytes_switch_algorithm(OQS_RAND_alg_nist_kat);
	if (ret != OQS_SUCCESS) {
		goto ossl_error;
	}
	OQS_randombytes_nist_kat_init(entropy_input, NULL, 256);
    
    ssl_ctx = SSL_CTX_new(ssl_meth);
    if (!ssl_ctx)
    {
        goto ossl_error;
    }

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
#ifndef TEST_PSK
    ret = SSL_CTX_load_verify_locations(ssl_ctx, "../tmp/nginx/conf/CA.crt", 0);
    if(ret != 1)
    {
        goto ossl_error;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

#else
    if (psk_key != NULL) {
        if (c_debug)
            BIO_printf(bio_c_out, "PSK key given, setting client callback\n");
        SSL_CTX_set_psk_client_callback(ssl_ctx, psk_client_cb);
    }
#endif

    while(measurements < measurements_to_make)
    {
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);
        ssl = do_tls_handshake(ssl_ctx);
        clock_gettime(CLOCK_MONOTONIC_RAW, &finish);
        if (!ssl)
        {
            /* Retry since at high packet loss rates,
             * the connect() syscall fails sometimes.
             * Non-retryable errors are caught by manual
             * inspection of logs, which has sufficed
             * for our purposes */
            continue;
        }

        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        ret = BIO_closesocket(SSL_get_fd(ssl));
        if(ret == -1)
        {
            goto ossl_error;
        }

        SSL_free(ssl);

        handshake_times_ms[measurements] = ((finish.tv_sec - start.tv_sec) * MS_IN_S) + ((finish.tv_nsec - start.tv_nsec) / NS_IN_MS);
        measurements++;
    }

    for(size_t i = 0; i < measurements - 1; i++)
    {
        printf("%f,", handshake_times_ms[i]);
    }
    printf("%f", handshake_times_ms[measurements - 1]);

    ret = 0;
    goto end;

ossl_error:
    fprintf(stderr, "Unrecoverable OpenSSL error.\n");
    ERR_print_errors_fp(stderr);
end:
    SSL_CTX_free(ssl_ctx);
    return ret;
}
