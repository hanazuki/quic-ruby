#ifndef QUIC_H
#define QUIC_H 1

#include "ruby.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>
#include <openssl/ssl.h>

extern VALUE rb_mQuic;
extern VALUE rb_mQuicConnection;
extern VALUE rb_cQuicConnectionClient;

void Init_quic_connection_client(VALUE rb_mQuicConnection);

#endif /* QUIC_H */
