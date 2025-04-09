//go:build ignore

#ifndef ECAPTURE_OPENSSL_3_5_0_KERN_H
#define ECAPTURE_OPENSSL_3_5_0_KERN_H

/* OPENSSL_VERSION_TEXT: OpenSSL 3.5.0 8 Apr 2025 */
/* OPENSSL_VERSION_NUMBER: 810549248 */

// ssl_st->type
#define SSL_ST_TYPE 0x0

// ssl_connection_st->version
#define SSL_CONNECTION_ST_VERSION 0x48

// ssl_connection_st->session
#define SSL_CONNECTION_ST_SESSION 0x900

// ssl_connection_st->s3
#define SSL_CONNECTION_ST_S3 0x160

// ssl_connection_st->rbio
#define SSL_CONNECTION_ST_RBIO 0x50

// ssl_connection_st->wbio
#define SSL_CONNECTION_ST_WBIO 0x58

// ssl_connection_st->server
#define SSL_CONNECTION_ST_SERVER 0x78

// ssl_session_st->master_key
#define SSL_SESSION_ST_MASTER_KEY 0x50

// ssl_connection_st->s3.client_random
#define SSL_CONNECTION_ST_S3_CLIENT_RANDOM 0x188

// ssl_session_st->cipher
#define SSL_SESSION_ST_CIPHER 0x2f8

// ssl_session_st->cipher_id
#define SSL_SESSION_ST_CIPHER_ID 0x300

// ssl_cipher_st->id
#define SSL_CIPHER_ST_ID 0x18

// ssl_connection_st->handshake_secret
#define SSL_CONNECTION_ST_HANDSHAKE_SECRET 0x5bc

// ssl_connection_st->handshake_traffic_hash
#define SSL_CONNECTION_ST_HANDSHAKE_TRAFFIC_HASH 0x73c

// ssl_connection_st->client_app_traffic_secret
#define SSL_CONNECTION_ST_CLIENT_APP_TRAFFIC_SECRET 0x77c

// ssl_connection_st->server_app_traffic_secret
#define SSL_CONNECTION_ST_SERVER_APP_TRAFFIC_SECRET 0x7bc

// ssl_connection_st->exporter_master_secret
#define SSL_CONNECTION_ST_EXPORTER_MASTER_SECRET 0x7fc

// bio_st->num
#define BIO_ST_NUM 0x38

#define SSL_ST_VERSION SSL_CONNECTION_ST_VERSION

#define SSL_ST_WBIO SSL_CONNECTION_ST_WBIO

#define SSL_ST_RBIO SSL_CONNECTION_ST_RBIO


#include "openssl.h"

#endif
