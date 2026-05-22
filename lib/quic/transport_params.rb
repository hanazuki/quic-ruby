# frozen_string_literal: true

module Quic
  TransportParams = Data.define(
    :initial_max_stream_data_bidi_local,
    :initial_max_stream_data_bidi_remote,
    :initial_max_stream_data_uni,
    :initial_max_data,
    :initial_max_streams_bidi,
    :initial_max_streams_uni,
    :max_idle_timeout,
    :active_connection_id_limit
  )

  class TransportParams
    def self.default
      new(
        initial_max_stream_data_bidi_local: 262_144,
        initial_max_stream_data_bidi_remote: 262_144,
        initial_max_stream_data_uni: 262_144,
        initial_max_data: 1_048_576,
        initial_max_streams_bidi: 100,
        initial_max_streams_uni: 100,
        max_idle_timeout: 30_000_000_000,
        active_connection_id_limit: 7
      )
    end
  end
end
