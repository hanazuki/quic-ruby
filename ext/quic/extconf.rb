# frozen_string_literal: true

require "mkmf"
require "mini_portile2"
require "shellwords"
require "fileutils"

LIBRESSL_VERSION = "4.3.1"
LIBRESSL_SHA256 = "c2db42ace14e7d5419826fab35a742ec6e4d12725a051a51d0cea3c10ba0fa50"
NGTCP2_VERSION = "1.22.1"
NGTCP2_SHA256 = "063d80531acac0ddbbc1b9d12829a824edc2abe8dba2e632fd1ce15cfd5632f9"
# The picotls revision that ngtcp2 1.22.1 is tested against (see ngtcp2's README).
PICOTLS_COMMIT = "b84869f41414b6d0148db7728f1cf12f5b544874"
PICOTLS_SHA256 = "abdb190f022d2ee2a3f3dd20e7303a226d7ec4e82f2221c0ab243d9a2e8ceaaf"
# Bump when ext/quic/patches/picotls/ changes; installed? only checks for the archive.
PICOTLS_PATCH_LEVEL = "p1"

# picotls has no release tarballs, and its CMake build needs the picotest
# submodule, which GitHub archive tarballs do not contain. Build only the two
# libraries we need (core + OpenSSL-API backend) into a single libpicotls.a.
class PicotlsRecipe < MiniPortile
  SOURCES = %w[lib/picotls.c lib/hpke.c lib/pembase64.c lib/openssl.c].freeze

  attr_accessor :openssl_include_path

  def configure
  end

  def configured?
    true
  end

  def compile
    cflags = %W[-std=gnu99 -O2 -fPIC -fvisibility=hidden -Iinclude -I#{openssl_include_path}]
    objects = SOURCES.map do |src|
      obj = File.basename(src, ".c") + ".o"
      execute("compile", [*cc_cmd.shellsplit, *cflags, "-c", src, "-o", obj])
      obj
    end
    ar = (ENV["AR"] || RbConfig::CONFIG["AR"] || "ar").shellsplit
    execute("compile", [*ar, "rcs", "libpicotls.a", *objects])
  end

  def install
    FileUtils.mkdir_p([lib_path, include_path])
    FileUtils.cp(File.join(work_path, "libpicotls.a"), lib_path)
    FileUtils.cp_r(Dir.glob(File.join(work_path, "include", "*")), include_path)
  end

  def installed?
    File.exist?(File.join(lib_path, "libpicotls.a"))
  end
end

libressl = MiniPortile.new("libressl", LIBRESSL_VERSION)
libressl.files = [{
  url: "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-#{LIBRESSL_VERSION}.tar.gz",
  sha256: LIBRESSL_SHA256
}]
libressl.configure_options = %w[--disable-shared --with-pic]
libressl.cook
libressl.activate

picotls = PicotlsRecipe.new("picotls", "#{PICOTLS_COMMIT[0, 7]}-#{PICOTLS_PATCH_LEVEL}")
picotls.files = [{
  url: "https://github.com/h2o/picotls/archive/#{PICOTLS_COMMIT}.tar.gz",
  sha256: PICOTLS_SHA256
}]
picotls.patch_files = Dir.glob(File.join(__dir__, "patches", "picotls", "*.patch")).sort
picotls.openssl_include_path = libressl.include_path
picotls.cook
# Deliberately no picotls.activate: mkmf_config passes -I/-L below, and not
# activating keeps the extra directory out of CPATH.

ngtcp2 = MiniPortile.new("ngtcp2", NGTCP2_VERSION)
ngtcp2.files = [{
  url: "https://github.com/ngtcp2/ngtcp2/releases/download/v#{NGTCP2_VERSION}/ngtcp2-#{NGTCP2_VERSION}.tar.gz",
  sha256: NGTCP2_SHA256
}]
# PKG_CONFIG_LIBDIR (not PKG_CONFIG_PATH) replaces the default search path
# instead of extending it, so a system openssl.pc cannot be picked up for the
# `openssl` entry in libngtcp2_crypto_picotls.pc's Requires.private.
ngtcp2.configure_options = [
  "--enable-lib-only",
  "--disable-shared",
  "--with-pic",
  # Skip the quictls/libressl/ossl helpers; only libngtcp2_crypto_picotls.
  "--without-openssl",
  "--with-picotls",
  # crypto/picotls declares lib_LIBRARIES, not lib_LTLIBRARIES, so it is built
  # by plain ar rather than libtool and --with-pic does not reach it. Without
  # -fPIC the archive cannot be linked into quic.so.
  "CFLAGS=-g -O2 -fPIC",
  "PKG_CONFIG_LIBDIR=#{libressl.path}/lib/pkgconfig",
  "PICOTLS_CFLAGS=-I#{picotls.include_path}",
  "PICOTLS_LIBS=-L#{picotls.lib_path} -lpicotls"
]
ngtcp2.cook
ngtcp2.activate

# Wire static archives into mkmf in reverse dependency order. mkmf_config
# prepends to $libs, so the leftmost entry on the final link line ends up being
# the last one we add here (ngtcp2_crypto_picotls), satisfying static-link
# ordering: ngtcp2_crypto_picotls -> ngtcp2 -> picotls -> ssl -> crypto.
#
# libssl is kept only so that the -lssl pulled in by
# libngtcp2_crypto_picotls.pc's Requires.private resolves to the vendored
# LibreSSL. Nothing references it, so no libssl object ends up in quic.so.
libressl.mkmf_config(pkg: "libcrypto", static: "crypto")
libressl.mkmf_config(pkg: "libssl", static: "ssl")
picotls.mkmf_config(static: "picotls")
ngtcp2.mkmf_config(pkg: "libngtcp2", static: "ngtcp2")
ngtcp2.mkmf_config(pkg: "libngtcp2_crypto_picotls", static: "ngtcp2_crypto_picotls")

abort "ngtcp2 header missing" unless have_header("ngtcp2/ngtcp2.h")
abort "picotls header missing" unless have_header("picotls.h")
abort "picotls/openssl.h missing" unless have_header("picotls/openssl.h")
abort "ngtcp2_crypto_picotls header missing" unless have_header("ngtcp2/ngtcp2_crypto_picotls.h")
abort "picotls was built without X25519 (patch not applied?)" unless try_compile(<<~C)
  #include <picotls/openssl.h>
  #if !PTLS_OPENSSL_HAVE_X25519
  #error X25519 unavailable
  #endif
C
# ngtcp2_conn_client_new and most other ngtcp2 entry points are exposed as
# ABI-versioned macros, so use non-macro symbols for link verification.
abort "libngtcp2 not linkable" unless have_func("ngtcp2_version", "ngtcp2/ngtcp2.h")
abort "libngtcp2_crypto_picotls not linkable" unless
  have_func("ngtcp2_crypto_picotls_configure_client_context", %w[picotls.h ngtcp2/ngtcp2_crypto_picotls.h])
abort "libcrypto not linkable" unless have_func("OpenSSL_version", "openssl/crypto.h")

# picotls has neither a version macro nor releases, so Quic.library_versions
# reports the commit the extension was built against.
append_cflags("-DQUIC_PICOTLS_COMMIT=\\\"#{PICOTLS_COMMIT}\\\"")
append_cflags("-fvisibility=hidden")

create_makefile("quic/quic")
