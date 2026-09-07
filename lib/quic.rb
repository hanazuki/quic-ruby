# frozen_string_literal: true

require_relative "quic/version"

module Quic
  class Error < StandardError
    attr_reader :code
  end
end

begin
  # precompiled gem: lib/quic/<ruby-api>/quic.so
  RUBY_VERSION =~ /(\d+\.\d+)/
  require "quic/#{$1}/quic"
rescue LoadError
  # source build: lib/quic/quic.so
  require "quic/quic"
end
require_relative "quic/transport_params"
require_relative "quic/settings"
require_relative "quic/connection"
require_relative "quic/stream"
