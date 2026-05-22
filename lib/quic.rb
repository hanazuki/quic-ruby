# frozen_string_literal: true

require_relative "quic/version"

module Quic
  class Error < StandardError
    attr_reader :code
  end
end

require "quic/quic"
require_relative "quic/transport_params"
require_relative "quic/settings"
require_relative "quic/connection"
