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

extern VALUE rb_eQuicError;
extern VALUE rb_eQuicErrorProto;
extern VALUE rb_eQuicErrorDropConn;
extern VALUE rb_eQuicErrorRetry;
extern VALUE rb_eQuicErrorClosed;
extern VALUE rb_eQuicErrorCryptoError;
extern VALUE rb_eQuicErrorHandshakeTimeout;
extern VALUE rb_eQuicErrorFlowControl;
extern VALUE rb_eQuicErrorUnknown;

void Init_quic_connection_client(VALUE rb_mQuicConnection);

/* Raise a Quic::Error subclass mapped from an ngtcp2 negative error code.
   Never returns. */
NORETURN(void quic_raise_ngtcp2_error(int rv));

#endif /* QUIC_H */
