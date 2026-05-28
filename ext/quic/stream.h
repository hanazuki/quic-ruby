#ifndef QUIC_STREAM_H
#define QUIC_STREAM_H 1

#include "quic.h"

extern VALUE rb_cQuicStream;

void Init_quic_stream(VALUE rb_mQuicArg);

/* Internal helpers used by connection_client.c stream callbacks and
   write_pkt's stream-aware path. */

typedef struct {
  int64_t stream_id;
  /* Cumulative bytes handed to ngtcp2 via writev_stream so far. Increases
     monotonically; used to derive the next send position within
     @pending_chunks. */
  uint64_t sent_offset;
  /* Cumulative bytes acked by the peer (per acked_stream_data_offset).
     Increases monotonically. */
  uint64_t acked_offset;
  /* Cumulative bytes shifted out of @pending_chunks. Always
     <= acked_offset (we only shift a Chunk after its end is acked). */
  uint64_t pending_shifted;
  bool fin_received;          /* recv_stream_data delivered FIN */
  bool fin_sent;              /* #write(fin: true) queued FIN */
  bool fin_flushed;           /* write_pkt actually wrote the FIN frame */
  bool reset;                 /* stream_reset callback fired */
  bool closed;                /* stream_close callback fired */
  uint64_t close_app_error_code;
  bool close_has_app_error_code;
} quic_stream_t;

extern const rb_data_type_t quic_stream_data_type;

/* Allocate a new Quic::Stream Ruby object with a zero-initialized
   quic_stream_t. Caller fills stream_id and ivars (@id / @client /
   @pending_chunks / @recv_buffer). */
VALUE quic_stream_new(int64_t stream_id, VALUE client);

#endif /* QUIC_STREAM_H */
