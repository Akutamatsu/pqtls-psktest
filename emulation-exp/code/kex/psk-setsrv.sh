#!/bin/bash
set -ex

ROOT="$(dirname $(pwd))"

OPENSSL=${ROOT}/tmp/openssl/apps/openssl
OPENSSL_CNF=${ROOT}/tmp/openssl/apps/openssl.cnf

# NGINX_APP=${ROOT}/tmp/nginx/sbin/nginx
# NGINX_CONF_DIR=${ROOT}/tmp/nginx/conf

##########################
# Build s_timer
##########################
make s_timer.o

##########################
# Setup network namespaces
##########################
${ROOT}/setup_ns.sh

##########################
# Start nginx(/server)
##########################
# cp nginx.conf ${NGINX_CONF_DIR}/nginx.conf
# ip netns exec srv_ns ${NGINX_APP}

ip netns exec srv_ns ${OPENSSL} s_server -quiet -tls1_3 -psk 8e8fb9cf7fab49b9fb2ba92ca4b9e217196d9a37917ca7a786347ee19a1efc70 -psk_identity zzdtest -ciphersuites TLS_AES_128_GCM_SHA256 -nocert
