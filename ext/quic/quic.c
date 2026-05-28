#include "quic.h"
#include "stream.h"

VALUE rb_mQuic;
VALUE rb_mQuicConnection;
VALUE rb_cQuicConnectionClient;

VALUE rb_eQuicError;
VALUE rb_eQuicErrorProto;
VALUE rb_eQuicErrorDropConn;
VALUE rb_eQuicErrorRetry;
VALUE rb_eQuicErrorClosed;
VALUE rb_eQuicErrorCryptoError;
VALUE rb_eQuicErrorHandshakeTimeout;
VALUE rb_eQuicErrorFlowControl;
VALUE rb_eQuicErrorUnknown;
VALUE rb_eQuicErrorWaitReadable;
VALUE rb_eQuicErrorWaitWritable;
VALUE rb_eQuicErrorStreamClosed;
VALUE rb_eQuicErrorStreamReset;
VALUE rb_eQuicErrorNotBound;

static VALUE
quic_library_versions(VALUE self)
{
  (void)self;
  VALUE h = rb_hash_new();
  rb_hash_aset(h, ID2SYM(rb_intern("ngtcp2")),
               rb_str_new_cstr(ngtcp2_version(0)->version_str));
  rb_hash_aset(h, ID2SYM(rb_intern("openssl")),
               rb_str_new_cstr(OpenSSL_version(OPENSSL_VERSION)));
  return h;
}

void
quic_raise_ngtcp2_error(int rv)
{
  VALUE cls;
  switch (rv) {
    case NGTCP2_ERR_PROTO:
      cls = rb_eQuicErrorProto;
      break;
    case NGTCP2_ERR_DROP_CONN:
      cls = rb_eQuicErrorDropConn;
      break;
    case NGTCP2_ERR_RETRY:
      cls = rb_eQuicErrorRetry;
      break;
    case NGTCP2_ERR_CLOSING:
    case NGTCP2_ERR_DRAINING:
      cls = rb_eQuicErrorClosed;
      break;
    case NGTCP2_ERR_IDLE_CLOSE:
      cls = rb_eQuicErrorClosed;
      break;
    case NGTCP2_ERR_CRYPTO:
      cls = rb_eQuicErrorCryptoError;
      break;
    case NGTCP2_ERR_HANDSHAKE_TIMEOUT:
      cls = rb_eQuicErrorHandshakeTimeout;
      break;
    case NGTCP2_ERR_STREAM_DATA_BLOCKED:
      cls = rb_eQuicErrorFlowControl;
      break;
    case NGTCP2_ERR_STREAM_SHUT_WR:
      cls = rb_eQuicErrorStreamClosed;
      break;
    default:
      cls = rb_eQuicErrorUnknown;
      break;
  }

  VALUE exc = rb_exc_new_cstr(cls, ngtcp2_strerror(rv));
  rb_ivar_set(exc, rb_intern("@code"), INT2NUM(rv));
  rb_exc_raise(exc);
}

RUBY_FUNC_EXPORTED void
Init_quic(void)
{
  rb_mQuic = rb_define_module("Quic");
  rb_mQuicConnection = rb_define_module_under(rb_mQuic, "Connection");
  rb_define_singleton_method(rb_mQuic, "library_versions", quic_library_versions, 0);

  /* Quic::Error is defined in Ruby (lib/quic.rb) before this Init_quic runs,
     so rb_const_get retrieves the already-defined base class. Subclasses live
     under Quic::Error::<Name>. */
  rb_eQuicError = rb_const_get(rb_mQuic, rb_intern("Error"));
  rb_eQuicErrorProto = rb_define_class_under(rb_eQuicError, "Proto", rb_eQuicError);
  rb_eQuicErrorDropConn = rb_define_class_under(rb_eQuicError, "DropConn", rb_eQuicError);
  rb_eQuicErrorRetry = rb_define_class_under(rb_eQuicError, "Retry", rb_eQuicError);
  rb_eQuicErrorClosed = rb_define_class_under(rb_eQuicError, "Closed", rb_eQuicError);
  rb_eQuicErrorCryptoError = rb_define_class_under(rb_eQuicError, "CryptoError", rb_eQuicError);
  rb_eQuicErrorHandshakeTimeout = rb_define_class_under(rb_eQuicError, "HandshakeTimeout", rb_eQuicError);
  rb_eQuicErrorFlowControl = rb_define_class_under(rb_eQuicError, "FlowControl", rb_eQuicError);
  rb_eQuicErrorUnknown = rb_define_class_under(rb_eQuicError, "Unknown", rb_eQuicError);

  /* IO-style non-blocking errors. Mix in the standard IO::Wait{Readable,Writable}
     modules so callers can `rescue IO::WaitReadable` (or the Quic subclass)
     interchangeably with stdlib IO objects. */
  VALUE io_wait_readable = rb_const_get(rb_cIO, rb_intern("WaitReadable"));
  VALUE io_wait_writable = rb_const_get(rb_cIO, rb_intern("WaitWritable"));
  rb_eQuicErrorWaitReadable = rb_define_class_under(rb_eQuicError, "WaitReadable", rb_eQuicError);
  rb_include_module(rb_eQuicErrorWaitReadable, io_wait_readable);
  rb_eQuicErrorWaitWritable = rb_define_class_under(rb_eQuicError, "WaitWritable", rb_eQuicError);
  rb_include_module(rb_eQuicErrorWaitWritable, io_wait_writable);

  rb_eQuicErrorStreamClosed = rb_define_class_under(rb_eQuicError, "StreamClosed", rb_eQuicError);
  rb_eQuicErrorStreamReset = rb_define_class_under(rb_eQuicError, "StreamReset", rb_eQuicError);
  rb_eQuicErrorNotBound = rb_define_class_under(rb_eQuicError, "NotBound", rb_eQuicError);

  Init_quic_connection_client(rb_mQuicConnection);
  Init_quic_stream(rb_mQuic);
}
