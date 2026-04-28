#include "quic.h"

VALUE rb_mQuic;

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

RUBY_FUNC_EXPORTED void
Init_quic(void)
{
  rb_mQuic = rb_define_module("Quic");
  rb_define_singleton_method(rb_mQuic, "library_versions", quic_library_versions, 0);
}
