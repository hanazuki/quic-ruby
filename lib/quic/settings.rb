# frozen_string_literal: true

module Quic
  Settings = Data.define(
    :cc_algo,
    :initial_rtt,
    :max_window,
    :max_stream_window,
    :handshake_timeout,
    :no_pmtud
  )

  class Settings
    def self.default
      new(
        cc_algo: :cubic,
        initial_rtt: 333_000_000,
        max_window: 0,
        max_stream_window: 0,
        handshake_timeout: 10_000_000_000,
        no_pmtud: false
      )
    end
  end
end
