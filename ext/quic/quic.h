#ifndef QUIC_H
#define QUIC_H 1

#include "ruby.h"
#include "ruby/encoding.h"

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
extern VALUE rb_eQuicErrorWaitReadable;
extern VALUE rb_eQuicErrorWaitWritable;
extern VALUE rb_eQuicErrorStreamClosed;
extern VALUE rb_eQuicErrorStreamReset;
extern VALUE rb_eQuicErrorNotBound;

void Init_quic_connection_client(VALUE rb_mQuicConnection);

/* Accessor used by stream.c to issue ngtcp2 calls (e.g.
   ngtcp2_conn_shutdown_stream_read) for streams that hold a back-reference
   to their parent Quic::Connection::Client via @client. Returns the raw
   ngtcp2_conn pointer; the caller is responsible for ensuring the Ruby
   Client object is alive for the duration of the call. */
ngtcp2_conn *quic_client_conn(VALUE client);

/* Raise a Quic::Error subclass mapped from an ngtcp2 negative error code.
   Never returns. */
NORETURN(void quic_raise_ngtcp2_error(int rv));

#endif /* QUIC_H */
