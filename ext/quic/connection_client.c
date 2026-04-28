#include "quic.h"

#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>

#include <openssl/rand.h>

static int quic_crypto_initialized = 0;

typedef struct {
  ngtcp2_conn *conn;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  ngtcp2_cid scid;
  ngtcp2_cid dcid;
} quic_client_t;

static void
quic_client_free(void *ptr)
{
  quic_client_t *c = (quic_client_t *)ptr;
  if (c->conn) ngtcp2_conn_del(c->conn);
  if (c->ssl) SSL_free(c->ssl);
  if (c->ssl_ctx) SSL_CTX_free(c->ssl_ctx);
  xfree(c);
}

static size_t
quic_client_size(const void *ptr)
{
  (void)ptr;
  return sizeof(quic_client_t);
}

static const rb_data_type_t quic_client_data_type = {
  "Quic::Connection::Client",
  {NULL, quic_client_free, quic_client_size,},
  NULL, NULL,
  RUBY_TYPED_FREE_IMMEDIATELY,
};

static VALUE
quic_client_alloc(VALUE klass)
{
  quic_client_t *c = ALLOC(quic_client_t);
  memset(c, 0, sizeof(*c));
  return TypedData_Wrap_Struct(klass, &quic_client_data_type, c);
}

static ngtcp2_tstamp
quic_now(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)ts.tv_nsec;
}

static void
quic_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
  (void)rand_ctx;
  RAND_bytes(dest, (int)destlen);
}

static int
quic_get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                              uint8_t *token, size_t cidlen, void *user_data)
{
  (void)conn;
  (void)user_data;
  if (RAND_bytes(cid->data, (int)cidlen) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  cid->datalen = cidlen;
  if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static void
quic_resolve_remote(const char *host, int port,
                    struct sockaddr_storage *out, socklen_t *outlen)
{
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  char port_s[16];

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  snprintf(port_s, sizeof(port_s), "%d", port);

  if (getaddrinfo(host, port_s, &hints, &res) == 0 && res != NULL) {
    memcpy(out, res->ai_addr, res->ai_addrlen);
    *outlen = res->ai_addrlen;
    freeaddrinfo(res);
    return;
  }

  struct sockaddr_in *sin = (struct sockaddr_in *)out;
  memset(sin, 0, sizeof(*sin));
  sin->sin_family = AF_INET;
  sin->sin_port = htons((uint16_t)port);
  *outlen = sizeof(*sin);
}

static VALUE
quic_client_initialize(int argc, VALUE *argv, VALUE self)
{
  VALUE opts = Qnil;
  rb_scan_args(argc, argv, "0:", &opts);
  if (NIL_P(opts)) {
    rb_raise(rb_eArgError, "missing keywords: host, port");
  }

  VALUE host_v = rb_hash_aref(opts, ID2SYM(rb_intern("host")));
  VALUE port_v = rb_hash_aref(opts, ID2SYM(rb_intern("port")));
  if (NIL_P(host_v) || NIL_P(port_v)) {
    rb_raise(rb_eArgError, "host: and port: are required");
  }
  Check_Type(host_v, T_STRING);
  int port = NUM2INT(port_v);

  rb_ivar_set(self, rb_intern("@host"), host_v);
  rb_ivar_set(self, rb_intern("@port"), port_v);

  if (!quic_crypto_initialized) {
    if (ngtcp2_crypto_quictls_init() != 0) {
      rb_raise(rb_eRuntimeError, "ngtcp2_crypto_quictls_init failed");
    }
    quic_crypto_initialized = 1;
  }

  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);

  c->ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (!c->ssl_ctx) {
    rb_raise(rb_eRuntimeError, "SSL_CTX_new failed");
  }
  if (ngtcp2_crypto_quictls_configure_client_context(c->ssl_ctx) != 0) {
    rb_raise(rb_eRuntimeError, "ngtcp2_crypto_quictls_configure_client_context failed");
  }

  c->ssl = SSL_new(c->ssl_ctx);
  if (!c->ssl) {
    rb_raise(rb_eRuntimeError, "SSL_new failed");
  }
  SSL_set_connect_state(c->ssl);
  SSL_set_tlsext_host_name(c->ssl, RSTRING_PTR(host_v));

  c->scid.datalen = 8;
  if (RAND_bytes(c->scid.data, 8) != 1) {
    rb_raise(rb_eRuntimeError, "RAND_bytes(scid) failed");
  }
  c->dcid.datalen = 8;
  if (RAND_bytes(c->dcid.data, 8) != 1) {
    rb_raise(rb_eRuntimeError, "RAND_bytes(dcid) failed");
  }

  ngtcp2_callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
  callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
  callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
  callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
  callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
  callbacks.update_key = ngtcp2_crypto_update_key_cb;
  callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
  callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  callbacks.rand = quic_rand_cb;
  callbacks.get_new_connection_id = quic_get_new_connection_id_cb;

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.initial_ts = quic_now();

  ngtcp2_transport_params params;
  ngtcp2_transport_params_default(&params);
  params.initial_max_stream_data_bidi_local = 256 * 1024;
  params.initial_max_stream_data_bidi_remote = 256 * 1024;
  params.initial_max_stream_data_uni = 256 * 1024;
  params.initial_max_data = 1024 * 1024;
  params.initial_max_streams_bidi = 100;
  params.initial_max_streams_uni = 100;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;
  params.active_connection_id_limit = 7;

  struct sockaddr_storage local_addr;
  struct sockaddr_storage remote_addr;
  socklen_t local_len;
  socklen_t remote_len;

  memset(&local_addr, 0, sizeof(local_addr));
  ((struct sockaddr_in *)&local_addr)->sin_family = AF_INET;
  local_len = sizeof(struct sockaddr_in);
  quic_resolve_remote(RSTRING_PTR(host_v), port, &remote_addr, &remote_len);

  ngtcp2_path path = {
    {(struct sockaddr *)&local_addr, local_len},
    {(struct sockaddr *)&remote_addr, remote_len},
    NULL,
  };

  int rv = ngtcp2_conn_client_new(&c->conn, &c->dcid, &c->scid, &path,
                                  NGTCP2_PROTO_VER_V1, &callbacks,
                                  &settings, &params, NULL, c);
  if (rv != 0) {
    rb_raise(rb_eRuntimeError, "ngtcp2_conn_client_new failed: %s", ngtcp2_strerror(rv));
  }

  ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);

  return self;
}

void
Init_quic_connection_client(VALUE rb_mQuicConnectionArg)
{
  rb_cQuicConnectionClient = rb_define_class_under(rb_mQuicConnectionArg, "Client", rb_cObject);
  rb_define_alloc_func(rb_cQuicConnectionClient, quic_client_alloc);
  rb_define_method(rb_cQuicConnectionClient, "initialize", quic_client_initialize, -1);
}
