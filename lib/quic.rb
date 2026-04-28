# frozen_string_literal: true

require_relative "quic/version"
require "quic/quic"
require_relative "quic/connection"

module Quic
  class Error < StandardError; end
end
