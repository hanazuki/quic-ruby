#include "quic.h"
#include "stream.h"

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include <openssl/rand.h>

/* Buffer size for #write_pkt. NGTCP2_MAX_UDP_PAYLOAD_SIZE (1200) is the
   minimum destlen ngtcp2 accepts. Revisit when PMTUD is enabled (Phase 4+). */
#define QUIC_WRITE_PKT_BUFLEN NGTCP2_MAX_UDP_PAYLOAD_SIZE

static int quic_crypto_initialized = 0;

typedef struct {
  ngtcp2_conn *conn;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  ngtcp2_cid scid;
  ngtcp2_cid dcid;
  /* ngtcp2 1.x requires applications to associate an ngtcp2_conn with the
     TLS object via SSL_set_app_data so that crypto callbacks (e.g.
     add_handshake_data) can recover the conn. The ref must outlive ssl. */
  ngtcp2_crypto_conn_ref conn_ref;
  /* Back-reference to the Quic::Connection::Client Ruby object that owns
     this struct. ngtcp2 stream callbacks receive a void* user_data equal
     to this struct, and they look up @streams via owner. We are stored
     INSIDE owner via TypedData_Wrap_Struct, so owner is guaranteed alive
     while we exist (no dmark needed). GC.compact may relocate owner and
     leave this field stale; a dcompact slot is a Phase 5 follow-up. */
  VALUE owner;
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

ngtcp2_conn *
quic_client_conn(VALUE client_v)
{
  quic_client_t *c;
  TypedData_Get_Struct(client_v, quic_client_t, &quic_client_data_type, c);
  return c->conn;
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

static ngtcp2_conn *
quic_client_get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
  return ((quic_client_t *)conn_ref->user_data)->conn;
}

static void
quic_require_binary(VALUE str, const char *name)
{
  Check_Type(str, T_STRING);
  if (rb_enc_get_index(str) != rb_ascii8bit_encindex()) {
    rb_raise(rb_eArgError, "%s must be ASCII-8BIT (binary) encoding", name);
  }
}

static uint64_t
quic_get_uint64_field(VALUE obj, const char *name)
{
  VALUE v = rb_funcall(obj, rb_intern(name), 0);
  return (uint64_t)NUM2ULL(v);
}

static ngtcp2_cc_algo
quic_cc_algo_from_sym(VALUE sym)
{
  Check_Type(sym, T_SYMBOL);
  ID id = SYM2ID(sym);
  if (id == rb_intern("reno"))  return NGTCP2_CC_ALGO_RENO;
  if (id == rb_intern("cubic")) return NGTCP2_CC_ALGO_CUBIC;
  if (id == rb_intern("bbr"))   return NGTCP2_CC_ALGO_BBR;
  rb_raise(rb_eArgError, "unknown cc_algo: %"PRIsVALUE" (expected :reno, :cubic, or :bbr)", sym);
}

static void
quic_fill_transport_params(ngtcp2_transport_params *params, VALUE tp)
{
  ngtcp2_transport_params_default(params);
  params->initial_max_stream_data_bidi_local =
    quic_get_uint64_field(tp, "initial_max_stream_data_bidi_local");
  params->initial_max_stream_data_bidi_remote =
    quic_get_uint64_field(tp, "initial_max_stream_data_bidi_remote");
  params->initial_max_stream_data_uni =
    quic_get_uint64_field(tp, "initial_max_stream_data_uni");
  params->initial_max_data =
    quic_get_uint64_field(tp, "initial_max_data");
  params->initial_max_streams_bidi =
    quic_get_uint64_field(tp, "initial_max_streams_bidi");
  params->initial_max_streams_uni =
    quic_get_uint64_field(tp, "initial_max_streams_uni");
  params->max_idle_timeout =
    (ngtcp2_duration)quic_get_uint64_field(tp, "max_idle_timeout");
  params->active_connection_id_limit =
    quic_get_uint64_field(tp, "active_connection_id_limit");
}

static void
quic_fill_settings(ngtcp2_settings *settings, VALUE st)
{
  ngtcp2_settings_default(settings);
  settings->initial_ts = quic_now();
  settings->cc_algo = quic_cc_algo_from_sym(rb_funcall(st, rb_intern("cc_algo"), 0));
  settings->initial_rtt =
    (ngtcp2_duration)quic_get_uint64_field(st, "initial_rtt");
  settings->max_window =
    quic_get_uint64_field(st, "max_window");
  settings->max_stream_window =
    quic_get_uint64_field(st, "max_stream_window");
  settings->handshake_timeout =
    (ngtcp2_duration)quic_get_uint64_field(st, "handshake_timeout");
  VALUE no_pmtud = rb_funcall(st, rb_intern("no_pmtud"), 0);
  settings->no_pmtud = RTEST(no_pmtud) ? 1 : 0;
}

/* Shared helper: look up the Quic::Stream registered for stream_id in the
   owner Client's @streams Hash. Returns Qnil if not found (which can happen
   if the stream was already removed by a previous stream_close callback). */
static VALUE
quic_client_lookup_stream(quic_client_t *c, int64_t stream_id)
{
  VALUE streams = rb_ivar_get(c->owner, rb_intern("@streams"));
  return rb_hash_aref(streams, LL2NUM(stream_id));
}

/* ngtcp2 stream callbacks. Each returns 0 on success or
   NGTCP2_ERR_CALLBACK_FAILURE on Ruby-side errors. We assume rb_str_buf_cat /
   rb_ary_* won't raise in normal operation (allocation failures aside, which
   would abort the process anyway), so we don't wrap in rb_protect for now. */

static int
quic_stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
  (void)conn;
  quic_client_t *c = (quic_client_t *)user_data;
  VALUE streams = rb_ivar_get(c->owner, rb_intern("@streams"));
  if (!NIL_P(rb_hash_aref(streams, LL2NUM(stream_id)))) {
    return 0;  /* already known (client-initiated) */
  }
  VALUE stream = quic_stream_new(stream_id, c->owner);
  rb_hash_aset(streams, LL2NUM(stream_id), stream);
  return 0;
}

static int
quic_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                         uint64_t offset, const uint8_t *data, size_t datalen,
                         void *user_data, void *stream_user_data)
{
  (void)conn;
  (void)offset;
  (void)stream_user_data;
  quic_client_t *c = (quic_client_t *)user_data;
  VALUE stream = quic_client_lookup_stream(c, stream_id);
  if (NIL_P(stream)) return 0;

  quic_stream_t *s;
  TypedData_Get_Struct(stream, quic_stream_t, &quic_stream_data_type, s);

  if (datalen > 0) {
    VALUE recv_buffer = rb_ivar_get(stream, rb_intern("@recv_buffer"));
    rb_str_buf_cat(recv_buffer, (const char *)data, (long)datalen);
  }
  if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
    s->fin_received = true;
  }
  return 0;
}

static int
quic_acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
                                 uint64_t offset, uint64_t datalen,
                                 void *user_data, void *stream_user_data)
{
  (void)conn;
  (void)offset;
  (void)stream_user_data;
  quic_client_t *c = (quic_client_t *)user_data;
  VALUE stream = quic_client_lookup_stream(c, stream_id);
  if (NIL_P(stream)) return 0;

  quic_stream_t *s;
  TypedData_Get_Struct(stream, quic_stream_t, &quic_stream_data_type, s);
  s->acked_offset += datalen;

  /* Shift any head Chunks of @pending_chunks whose end-offset is fully
     covered by acked_offset. Each Chunk's start-offset in the stream is
     pending_shifted (after previous shifts); its end-offset is
     pending_shifted + RSTRING_LEN(head). */
  VALUE pending = rb_ivar_get(stream, rb_intern("@pending_chunks"));
  while (RARRAY_LEN(pending) > 0) {
    VALUE head = RARRAY_AREF(pending, 0);
    uint64_t head_end = s->pending_shifted + (uint64_t)RSTRING_LEN(head);
    if (head_end <= s->acked_offset) {
      rb_ary_shift(pending);
      s->pending_shifted = head_end;
    } else {
      break;
    }
  }
  return 0;
}

static int
quic_stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t app_error_code, void *user_data,
                     void *stream_user_data)
{
  (void)conn;
  (void)stream_user_data;
  quic_client_t *c = (quic_client_t *)user_data;
  VALUE streams = rb_ivar_get(c->owner, rb_intern("@streams"));
  VALUE stream = rb_hash_aref(streams, LL2NUM(stream_id));
  if (NIL_P(stream)) return 0;

  quic_stream_t *s;
  TypedData_Get_Struct(stream, quic_stream_t, &quic_stream_data_type, s);
  s->closed = true;
  if (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) {
    s->close_has_app_error_code = true;
    s->close_app_error_code = app_error_code;
  }
  rb_hash_delete(streams, LL2NUM(stream_id));
  return 0;
}

static int
quic_stream_reset_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                     uint64_t app_error_code, void *user_data,
                     void *stream_user_data)
{
  (void)conn;
  (void)final_size;
  (void)stream_user_data;
  quic_client_t *c = (quic_client_t *)user_data;
  VALUE stream = quic_client_lookup_stream(c, stream_id);
  if (NIL_P(stream)) return 0;

  quic_stream_t *s;
  TypedData_Get_Struct(stream, quic_stream_t, &quic_stream_data_type, s);
  s->reset = true;
  s->close_app_error_code = app_error_code;
  s->close_has_app_error_code = true;
  return 0;
}

static VALUE
quic_client_open(int argc, VALUE *argv, VALUE klass)
{
  VALUE opts = Qnil;
  rb_scan_args(argc, argv, "0:", &opts);
  if (NIL_P(opts)) {
    rb_raise(rb_eArgError,
             "missing keywords: local_sockaddr, remote_sockaddr, server_name, transport_params, settings");
  }

  VALUE local_sockaddr   = rb_hash_aref(opts, ID2SYM(rb_intern("local_sockaddr")));
  VALUE remote_sockaddr  = rb_hash_aref(opts, ID2SYM(rb_intern("remote_sockaddr")));
  VALUE server_name      = rb_hash_aref(opts, ID2SYM(rb_intern("server_name")));
  VALUE transport_params = rb_hash_aref(opts, ID2SYM(rb_intern("transport_params")));
  VALUE settings_v       = rb_hash_aref(opts, ID2SYM(rb_intern("settings")));

  if (NIL_P(local_sockaddr) || NIL_P(remote_sockaddr) || NIL_P(server_name) ||
      NIL_P(transport_params) || NIL_P(settings_v)) {
    rb_raise(rb_eArgError,
             "all keywords required: local_sockaddr, remote_sockaddr, server_name, transport_params, settings");
  }

  quic_require_binary(local_sockaddr,  "local_sockaddr");
  quic_require_binary(remote_sockaddr, "remote_sockaddr");
  Check_Type(server_name, T_STRING);

  if (!quic_crypto_initialized) {
    if (ngtcp2_crypto_quictls_init() != 0) {
      rb_raise(rb_eRuntimeError, "ngtcp2_crypto_quictls_init failed");
    }
    quic_crypto_initialized = 1;
  }

  VALUE self = quic_client_alloc(klass);
  rb_ivar_set(self, rb_intern("@server_name"), server_name);

  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);
  c->owner = self;

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
  SSL_set_tlsext_host_name(c->ssl, RSTRING_PTR(server_name));

  VALUE alpn_ary = rb_funcall(settings_v, rb_intern("alpn"), 0);
  Check_Type(alpn_ary, T_ARRAY);
  long n_alpn = RARRAY_LEN(alpn_ary);
  if (n_alpn > 0) {
    /* RFC 7301 wire format: 1-byte length prefix + bytes, concatenated. */
    size_t total = 0;
    for (long i = 0; i < n_alpn; i++) {
      VALUE entry = RARRAY_AREF(alpn_ary, i);
      Check_Type(entry, T_STRING);
      long len = RSTRING_LEN(entry);
      if (len < 1 || len > 255) {
        rb_raise(rb_eArgError, "alpn entry must be 1-255 bytes (got %ld)", len);
      }
      total += 1 + (size_t)len;
    }
    /* total <= 256 * 256 = 65536; ALLOCA_N is safe at this size. */
    unsigned char *wire = ALLOCA_N(unsigned char, total);
    unsigned char *p = wire;
    for (long i = 0; i < n_alpn; i++) {
      VALUE entry = RARRAY_AREF(alpn_ary, i);
      long len = RSTRING_LEN(entry);
      *p++ = (unsigned char)len;
      memcpy(p, RSTRING_PTR(entry), (size_t)len);
      p += len;
    }
    /* SSL_set_alpn_protos returns 0 on success (counter-intuitive). */
    if (SSL_set_alpn_protos(c->ssl, wire, (unsigned int)total) != 0) {
      rb_raise(rb_eRuntimeError, "SSL_set_alpn_protos failed");
    }
  }

  /* Link the SSL handle back to this client so ngtcp2's crypto callbacks
     (add_handshake_data, set_encryption_secrets, ...) can resolve the
     ngtcp2_conn via SSL_get_app_data -> ngtcp2_crypto_conn_ref. */
  c->conn_ref.get_conn = quic_client_get_conn;
  c->conn_ref.user_data = c;
  SSL_set_app_data(c->ssl, &c->conn_ref);

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
  callbacks.stream_open = quic_stream_open_cb;
  callbacks.recv_stream_data = quic_recv_stream_data_cb;
  callbacks.acked_stream_data_offset = quic_acked_stream_data_offset_cb;
  callbacks.stream_close = quic_stream_close_cb;
  callbacks.stream_reset = quic_stream_reset_cb;

  ngtcp2_settings settings;
  quic_fill_settings(&settings, settings_v);

  ngtcp2_transport_params params;
  quic_fill_transport_params(&params, transport_params);

  ngtcp2_path path = {
    {(struct sockaddr *)RSTRING_PTR(local_sockaddr),  (ngtcp2_socklen)RSTRING_LEN(local_sockaddr)},
    {(struct sockaddr *)RSTRING_PTR(remote_sockaddr), (ngtcp2_socklen)RSTRING_LEN(remote_sockaddr)},
    NULL,
  };

  int rv = ngtcp2_conn_client_new(&c->conn, &c->dcid, &c->scid, &path,
                                  NGTCP2_PROTO_VER_V1, &callbacks,
                                  &settings, &params, NULL, c);
  if (rv != 0) {
    quic_raise_ngtcp2_error(rv);
  }

  ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);

  /* Stream registry: stream_id (Integer) -> Quic::Stream.
     Populated by #open_bidi_stream / #open_uni_stream and the stream_open
     callback. Entries are removed in the stream_close callback. */
  rb_ivar_set(self, rb_intern("@streams"), rb_hash_new());

  return self;
}

/* Find the first stream in @streams that has either pending bytes or a
   pending FIN to flush. Phase 4 minimum: linear scan, take the first match
   (no round-robin). Sets *out_datav to the byte slice to send, *out_datavcnt
   to 0 or 1, *out_flags to NGTCP2_WRITE_STREAM_FLAG_FIN when applicable.
   Returns the stream's Ruby VALUE (or Qnil if no candidate). */
static VALUE
quic_client_pick_send_stream(VALUE self, ngtcp2_vec *out_datav,
                             size_t *out_datavcnt, uint32_t *out_flags,
                             int64_t *out_stream_id)
{
  VALUE streams = rb_ivar_get(self, rb_intern("@streams"));
  VALUE stream_values = rb_funcall(streams, rb_intern("values"), 0);

  for (long i = 0; i < RARRAY_LEN(stream_values); i++) {
    VALUE st = RARRAY_AREF(stream_values, i);
    quic_stream_t *s;
    TypedData_Get_Struct(st, quic_stream_t, &quic_stream_data_type, s);
    if (s->fin_flushed) continue;

    VALUE pending = rb_ivar_get(st, rb_intern("@pending_chunks"));
    uint64_t position = s->sent_offset - s->pending_shifted;
    long chunks_count = RARRAY_LEN(pending);

    /* Walk pending Chunks to find the one containing the next unsent byte. */
    long chunk_idx = -1;
    long offset_in_chunk = 0;
    for (long j = 0; j < chunks_count; j++) {
      VALUE chunk = RARRAY_AREF(pending, j);
      long clen = RSTRING_LEN(chunk);
      if (position < (uint64_t)clen) {
        chunk_idx = j;
        offset_in_chunk = (long)position;
        break;
      }
      position -= (uint64_t)clen;
    }

    if (chunk_idx >= 0) {
      VALUE chunk = RARRAY_AREF(pending, chunk_idx);
      out_datav->base = (uint8_t *)RSTRING_PTR(chunk) + offset_in_chunk;
      out_datav->len = (size_t)(RSTRING_LEN(chunk) - offset_in_chunk);
      *out_datavcnt = 1;
      *out_stream_id = s->stream_id;
      /* Attach FIN if this is the LAST chunk and we're going to send all
         remaining bytes of it (ngtcp2 may encode less, in which case FIN
         won't actually be flushed and we'll retry next call). */
      *out_flags = (s->fin_sent && chunk_idx == chunks_count - 1)
                     ? NGTCP2_WRITE_STREAM_FLAG_FIN
                     : 0;
      return st;
    }

    if (s->fin_sent && !s->fin_flushed) {
      /* No data to send but a pending FIN-only frame. */
      out_datav->base = NULL;
      out_datav->len = 0;
      *out_datavcnt = 0;
      *out_stream_id = s->stream_id;
      *out_flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
      return st;
    }
  }

  return Qnil;
}

static VALUE
quic_client_write_pkt(int argc, VALUE *argv, VALUE self)
{
  VALUE buffer = Qnil;
  rb_scan_args(argc, argv, "01", &buffer);

  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);

  if (NIL_P(buffer)) {
    /* rb_str_buf_new returns an ASCII-8BIT (binary) String per CRuby spec,
       so no explicit rb_enc_associate is required. */
    buffer = rb_str_buf_new(QUIC_WRITE_PKT_BUFLEN);
  } else {
    Check_Type(buffer, T_STRING);
    if (rb_enc_get_index(buffer) != rb_ascii8bit_encindex()) {
      rb_raise(rb_eArgError, "buffer must be ASCII-8BIT (binary) encoding");
    }
    if (RSTRING_LEN(buffer) < (long)QUIC_WRITE_PKT_BUFLEN) {
      rb_str_modify_expand(buffer, (long)QUIC_WRITE_PKT_BUFLEN - RSTRING_LEN(buffer));
    }
  }

  ngtcp2_path_storage path_storage;
  ngtcp2_path_storage_zero(&path_storage);

  ngtcp2_pkt_info pi;
  memset(&pi, 0, sizeof(pi));

  uint8_t *dest = (uint8_t *)RSTRING_PTR(buffer);
  size_t destlen = (size_t)QUIC_WRITE_PKT_BUFLEN;

  /* Stream-aware path: if any stream has pending bytes or a pending FIN,
     route the packet through ngtcp2_conn_writev_stream so the stream data
     gets framed alongside connection-level frames. Falls back to conn-only
     when no stream is queued. */
  ngtcp2_vec datav;
  size_t datavcnt = 0;
  uint32_t writev_flags = 0;
  int64_t send_stream_id = -1;
  VALUE selected_stream = quic_client_pick_send_stream(
    self, &datav, &datavcnt, &writev_flags, &send_stream_id);

  ngtcp2_ssize pdatalen = -1;
  ngtcp2_ssize n = ngtcp2_conn_writev_stream(
    c->conn, &path_storage.path, &pi, dest, destlen, &pdatalen,
    writev_flags, send_stream_id, &datav, datavcnt, quic_now());

  if (n < 0) {
    /* ngtcp2 does not partially write on failure, but truncate explicitly so
       that a rescued caller cannot accidentally transmit stale bytes. */
    rb_str_set_len(buffer, 0);
    quic_raise_ngtcp2_error((int)n);
  }

  /* Update the selected stream's accounting only when we actually sent
     bytes. pdatalen >= 0 means ngtcp2 framed that many data bytes into the
     packet; if 0, no data was framed (but the packet may still contain ACK
     or other frames). */
  if (!NIL_P(selected_stream) && pdatalen > 0) {
    quic_stream_t *s;
    TypedData_Get_Struct(selected_stream, quic_stream_t,
                         &quic_stream_data_type, s);
    s->sent_offset += (uint64_t)pdatalen;
    /* FIN is only actually written when all requested data fits in the
       frame (see ngtcp2 docs on NGTCP2_WRITE_STREAM_FLAG_FIN). */
    if ((writev_flags & NGTCP2_WRITE_STREAM_FLAG_FIN) &&
        (size_t)pdatalen == datav.len) {
      s->fin_flushed = true;
    }
  } else if (!NIL_P(selected_stream) && datavcnt == 0 && n > 0 &&
             (writev_flags & NGTCP2_WRITE_STREAM_FLAG_FIN)) {
    /* FIN-only packet (no data) was successfully written. */
    quic_stream_t *s;
    TypedData_Get_Struct(selected_stream, quic_stream_t,
                         &quic_stream_data_type, s);
    s->fin_flushed = true;
  }

  if (n == 0) {
    rb_str_set_len(buffer, 0);
    return Qnil;
  }
  rb_str_set_len(buffer, n);
  return buffer;
}

struct quic_read_pkt_args {
  quic_client_t *c;
  VALUE packet;
  ngtcp2_path path;
  ngtcp2_pkt_info pi;
};

static VALUE
quic_read_pkt_body(VALUE arg)
{
  struct quic_read_pkt_args *a = (struct quic_read_pkt_args *)arg;
  int rv = ngtcp2_conn_read_pkt(a->c->conn, &a->path, &a->pi,
                                (const uint8_t *)RSTRING_PTR(a->packet),
                                (size_t)RSTRING_LEN(a->packet),
                                quic_now());
  if (rv != 0) {
    /* NORETURN: longjmp passes through rb_ensure so unlock still fires. */
    quic_raise_ngtcp2_error(rv);
  }
  return Qnil;
}

static VALUE
quic_read_pkt_unlock(VALUE arg)
{
  rb_str_unlocktmp(((struct quic_read_pkt_args *)arg)->packet);
  return Qnil;
}

static VALUE
quic_client_read_pkt(int argc, VALUE *argv, VALUE self)
{
  VALUE packet = Qnil;
  VALUE opts = Qnil;
  rb_scan_args(argc, argv, "1:", &packet, &opts);

  if (NIL_P(opts)) {
    rb_raise(rb_eArgError, "missing keywords: local_sockaddr, remote_sockaddr");
  }

  VALUE local_sockaddr  = rb_hash_aref(opts, ID2SYM(rb_intern("local_sockaddr")));
  VALUE remote_sockaddr = rb_hash_aref(opts, ID2SYM(rb_intern("remote_sockaddr")));

  if (NIL_P(local_sockaddr) || NIL_P(remote_sockaddr)) {
    rb_raise(rb_eArgError, "missing keywords: local_sockaddr, remote_sockaddr");
  }

  quic_require_binary(packet,          "packet");
  quic_require_binary(local_sockaddr,  "local_sockaddr");
  quic_require_binary(remote_sockaddr, "remote_sockaddr");

  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);

  struct quic_read_pkt_args args;
  args.c = c;
  args.packet = packet;
  args.path.local.addr     = (struct sockaddr *)RSTRING_PTR(local_sockaddr);
  args.path.local.addrlen  = (ngtcp2_socklen)RSTRING_LEN(local_sockaddr);
  args.path.remote.addr    = (struct sockaddr *)RSTRING_PTR(remote_sockaddr);
  args.path.remote.addrlen = (ngtcp2_socklen)RSTRING_LEN(remote_sockaddr);
  args.path.user_data      = NULL;
  memset(&args.pi, 0, sizeof(args.pi));

  rb_str_locktmp(packet);
  return rb_ensure(quic_read_pkt_body, (VALUE)&args,
                   quic_read_pkt_unlock, (VALUE)&args);
}

static VALUE
quic_client_handshake_completed_p(VALUE self)
{
  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);
  return ngtcp2_conn_get_handshake_completed(c->conn) ? Qtrue : Qfalse;
}

static VALUE
quic_client_in_closing_period_p(VALUE self)
{
  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);
  return ngtcp2_conn_in_closing_period(c->conn) ? Qtrue : Qfalse;
}

static VALUE
quic_client_in_draining_period_p(VALUE self)
{
  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);
  return ngtcp2_conn_in_draining_period(c->conn) ? Qtrue : Qfalse;
}

static VALUE
quic_client_expiry(VALUE self)
{
  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);
  ngtcp2_tstamp t = ngtcp2_conn_get_expiry(c->conn);
  if (t == UINT64_MAX) return Qnil;
  return ULL2NUM((unsigned long long)t);
}

/* Caller is responsible for ordering with #read_pkt / #write_pkt:
   read_pkt or handle_expiry to advance ngtcp2 state, then write_pkt to flush. */
static VALUE
quic_client_handle_expiry(VALUE self)
{
  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);
  int rv = ngtcp2_conn_handle_expiry(c->conn, quic_now());
  if (rv != 0) quic_raise_ngtcp2_error(rv);
  return Qnil;
}

static VALUE
quic_client_open_bidi_stream(VALUE self)
{
  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);

  int64_t stream_id;
  int rv = ngtcp2_conn_open_bidi_stream(c->conn, &stream_id, NULL);
  if (rv != 0) quic_raise_ngtcp2_error(rv);

  VALUE stream = quic_stream_new(stream_id, self);
  VALUE streams = rb_ivar_get(self, rb_intern("@streams"));
  rb_hash_aset(streams, LL2NUM(stream_id), stream);
  return stream;
}

static VALUE
quic_client_open_uni_stream(VALUE self)
{
  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);

  int64_t stream_id;
  int rv = ngtcp2_conn_open_uni_stream(c->conn, &stream_id, NULL);
  if (rv != 0) quic_raise_ngtcp2_error(rv);

  VALUE stream = quic_stream_new(stream_id, self);
  VALUE streams = rb_ivar_get(self, rb_intern("@streams"));
  rb_hash_aset(streams, LL2NUM(stream_id), stream);
  return stream;
}

void
Init_quic_connection_client(VALUE rb_mQuicConnectionArg)
{
  rb_cQuicConnectionClient = rb_define_class_under(rb_mQuicConnectionArg, "Client", rb_cObject);
  rb_define_alloc_func(rb_cQuicConnectionClient, quic_client_alloc);
  rb_define_singleton_method(rb_cQuicConnectionClient, "_open", quic_client_open, -1);
  rb_define_method(rb_cQuicConnectionClient, "write_pkt", quic_client_write_pkt, -1);
  rb_define_method(rb_cQuicConnectionClient, "read_pkt",  quic_client_read_pkt,  -1);
  rb_define_method(rb_cQuicConnectionClient, "expiry", quic_client_expiry, 0);
  rb_define_method(rb_cQuicConnectionClient, "handle_expiry", quic_client_handle_expiry, 0);
  rb_define_method(rb_cQuicConnectionClient, "handshake_completed?", quic_client_handshake_completed_p, 0);
  rb_define_method(rb_cQuicConnectionClient, "in_closing_period?", quic_client_in_closing_period_p, 0);
  rb_define_method(rb_cQuicConnectionClient, "in_draining_period?", quic_client_in_draining_period_p, 0);
  rb_define_method(rb_cQuicConnectionClient, "open_bidi_stream", quic_client_open_bidi_stream, 0);
  rb_define_method(rb_cQuicConnectionClient, "open_uni_stream", quic_client_open_uni_stream, 0);
}
