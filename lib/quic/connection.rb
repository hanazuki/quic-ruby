# frozen_string_literal: true

require "socket"

module Quic
  module Connection
    class Client
      def self.new(host:, port:, transport_params: nil, settings: nil)
        remote_sockaddr = Addrinfo.udp(host, port).to_sockaddr
        local_sockaddr = Addrinfo.udp("0.0.0.0", 0).to_sockaddr

        client = _open(
          local_sockaddr: local_sockaddr,
          remote_sockaddr: remote_sockaddr,
          server_name: host,
          transport_params: transport_params || Quic::TransportParams.default,
          settings: settings || Quic::Settings.default
        )
        client.instance_variable_set(:@host, host)
        client.instance_variable_set(:@port, port)
        client
      end
    end
  end
end
