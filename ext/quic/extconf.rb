# frozen_string_literal: true

require "mkmf"
require "mini_portile2"

LIBRESSL_VERSION = "4.3.1"
LIBRESSL_SHA256 = "c2db42ace14e7d5419826fab35a742ec6e4d12725a051a51d0cea3c10ba0fa50"
NGTCP2_VERSION = "1.22.1"
NGTCP2_SHA256 = "063d80531acac0ddbbc1b9d12829a824edc2abe8dba2e632fd1ce15cfd5632f9"

libressl = MiniPortile.new("libressl", LIBRESSL_VERSION)
libressl.files = [{
  url: "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-#{LIBRESSL_VERSION}.tar.gz",
  sha256: LIBRESSL_SHA256
}]
libressl.configure_options = %w[--disable-shared --with-pic]
libressl.cook
libressl.activate

ngtcp2 = MiniPortile.new("ngtcp2", NGTCP2_VERSION)
ngtcp2.files = [{
  url: "https://github.com/ngtcp2/ngtcp2/releases/download/v#{NGTCP2_VERSION}/ngtcp2-#{NGTCP2_VERSION}.tar.gz",
  sha256: NGTCP2_SHA256
}]
ngtcp2.configure_options = %W[
  --enable-lib-only
  --disable-shared
  --with-pic
  PKG_CONFIG_PATH=#{libressl.path}/lib/pkgconfig
]
ngtcp2.cook
ngtcp2.activate

# Wire static archives into mkmf in reverse dependency order. mkmf_config
# prepends to $libs, so the leftmost entry on the final link line ends up being
# the last one we add here (ngtcp2_crypto_libressl), satisfying static-link
# ordering: ngtcp2_crypto_libressl -> ngtcp2 -> ssl -> crypto.
libressl.mkmf_config(pkg: "libcrypto", static: "crypto")
libressl.mkmf_config(pkg: "libssl", static: "ssl")
ngtcp2.mkmf_config(pkg: "libngtcp2", static: "ngtcp2")
ngtcp2.mkmf_config(pkg: "libngtcp2_crypto_libressl", static: "ngtcp2_crypto_libressl")

abort "ngtcp2 header missing" unless have_header("ngtcp2/ngtcp2.h")
abort "ngtcp2_crypto_quictls header missing" unless have_header("ngtcp2/ngtcp2_crypto_quictls.h")
abort "openssl/ssl.h missing" unless have_header("openssl/ssl.h")
# ngtcp2_conn_client_new and most other ngtcp2 entry points are exposed as
# ABI-versioned macros, so use non-macro symbols for link verification.
abort "libngtcp2 not linkable" unless have_func("ngtcp2_version", "ngtcp2/ngtcp2.h")
abort "libngtcp2_crypto_libressl not linkable" unless have_func("ngtcp2_crypto_quictls_init", "ngtcp2/ngtcp2_crypto_quictls.h")
abort "libssl not linkable" unless have_func("OpenSSL_version", "openssl/opensslv.h")

append_cflags("-fvisibility=hidden")
append_ldflags("-Wl,--exclude-libs,ALL")  # Unexport symbols from statically linked libraries

create_makefile("quic/quic")
