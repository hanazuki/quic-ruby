# frozen_string_literal: true

require "socket"

module Quic
  module Connection
    class Client
      attr_reader :remote_address

      # Build a Client and pin a single peer address. address_family takes a
      # Symbol (:inet for IPv4, :inet6 for IPv6) or nil to defer family
      # selection to Addrinfo.udp's implicit resolution. Pin the resolved
      # Addrinfo into @remote_address so callers can match their UDPSocket's
      # connected sockaddr (otherwise DNS round-robin between Client.new and
      # sock.connect can produce a path that ngtcp2 silently drops).
      def self.new(host:, port:, address_family: nil, transport_params: nil, settings: nil)
        family = case address_family
        when nil then nil
        when :inet then Socket::AF_INET
        when :inet6 then Socket::AF_INET6
        else
          raise ArgumentError, "unknown address_family: #{address_family.inspect}"
        end

        remote_address = if family
          Addrinfo.getaddrinfo(host, port, family, :DGRAM, Socket::IPPROTO_UDP).first
        else
          Addrinfo.udp(host, port)
        end

        remote_sockaddr = remote_address.to_sockaddr
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
        client.instance_variable_set(:@remote_address, remote_address)
        client
      end

      # Attach an IO.select / #send / #recvfrom-compatible UDP socket so that
      # #run and Stream blocking I/O can drive the wire transparently. Caller
      # is responsible for socket lifetime; we do not close it. The socket
      # must already be #connect'd to the peer (we read #remote_address).
      def bind(sock)
        @sock = sock
        self
      end

      def bound_socket
        @sock
      end

      # Drive the handshake to completion using the bound socket. Raises
      # Quic::Error::NotBound if #bind has not been called. Propagates any
      # Quic::Error subclass raised by #read_pkt / #handle_expiry.
      def run
        raise Quic::Error::NotBound, "Quic::Connection::Client#bind(sock) has not been called" if @sock.nil?

        pump_until { handshake_completed? }
      end

      # One iteration of the I/O loop: drain any outgoing packets via
      # #write_pkt, then wait up to `timeout` (or the next ngtcp2 expiry,
      # whichever is sooner) for either an incoming datagram or the timer to
      # fire. Public-ish so Stream blocking ops can share it; documented as
      # "internal" for users.
      def pump_once(timeout: nil)
        raise Quic::Error::NotBound, "Quic::Connection::Client#bind(sock) has not been called" if @sock.nil?

        while (pkt = write_pkt)
          @sock.send(pkt, 0)
        end

        wait_for = pump_timeout(timeout)
        ready = IO.select([@sock], nil, nil, wait_for)
        if ready
          data, _addr = @sock.recvfrom(2048)
          # Reuse the same path tuple that Client.new / Client._open passed to
          # ngtcp2_conn_client_new so the read_pkt path matches the stored
          # connection path. local is 0.0.0.0:0 (Client.new convention) and
          # remote comes from the connected socket (assumes #connect was used).
          read_pkt(
            data,
            local_sockaddr: pump_local_sockaddr,
            remote_sockaddr: pump_remote_sockaddr
          )
        else
          handle_expiry
        end
      end

      # Iterate pump_once until `pred` returns truthy. Public so Stream
      # blocking methods can share it.
      def pump_until(&pred)
        pump_once until pred.call
      end

      private

      def pump_timeout(caller_timeout)
        ngtcp2_expiry_ns = expiry
        if ngtcp2_expiry_ns.nil?
          return caller_timeout
        end
        now_ns = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
        expiry_secs = [(ngtcp2_expiry_ns - now_ns) / 1_000_000_000.0, 0.0].max
        return expiry_secs if caller_timeout.nil?
        [caller_timeout, expiry_secs].min
      end

      def pump_local_sockaddr
        @pump_local_sockaddr ||= Addrinfo.udp("0.0.0.0", 0).to_sockaddr
      end

      def pump_remote_sockaddr
        @pump_remote_sockaddr ||= @sock.remote_address.to_sockaddr
      end
    end
  end
end
