#include "quic.h"

VALUE rb_mQuic;

RUBY_FUNC_EXPORTED void
Init_quic(void)
{
  rb_mQuic = rb_define_module("Quic");
}
