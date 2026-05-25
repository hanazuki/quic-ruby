# frozen_string_literal: true

require "test_helper"
require "socket"

class TestQuicE2E < Minitest::Test
  TARGET_HOST = "cloudflare-quic.com"
  TARGET_PORT = 443
  TIMEOUT_SEC = 10

  def setup
    skip "set EXTERNAL=1 to run E2E tests" unless ENV["EXTERNAL"] == "1"
  end

  def test_handshake_completes_against_public_server
    # Resolve once to IPv4 and reuse the same Addrinfo for the socket and the
    # connection path. cloudflare-quic.com has multiple A/AAAA records and the
    # default Addrinfo.udp picks any of them, so a separate resolution inside
    # Quic::Connection::Client.new vs. UDPSocket#connect can return different
    # IPs (or different address families) and ngtcp2 then rejects every reply
    # with "ignore packet from unknown path". Calling _open directly with a
    # pre-resolved sockaddr ensures both sides agree on the path.
    addr = Addrinfo.getaddrinfo(TARGET_HOST, TARGET_PORT, Socket::AF_INET, Socket::SOCK_DGRAM).first
    remote_sockaddr = addr.to_sockaddr
    local_sockaddr = Addrinfo.udp("0.0.0.0", 0).to_sockaddr

    sock = UDPSocket.new
    sock.connect(addr.ip_address, addr.ip_port)

    settings = Quic::Settings.default.with(alpn: ["h3"])
    client = Quic::Connection::Client._open(
      local_sockaddr: local_sockaddr,
      remote_sockaddr: remote_sockaddr,
      server_name: TARGET_HOST,
      transport_params: Quic::TransportParams.default,
      settings: settings
    )

    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + TIMEOUT_SEC

    until client.handshake_completed?
      flunk "handshake timed out" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      flunk "connection entered closing/draining before handshake" if client.in_closing_period? || client.in_draining_period?

      while (pkt = client.write_pkt)
        sock.send(pkt, 0)
      end

      expiry = client.expiry
      now_ns = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
      io_timeout = expiry ? [(expiry - now_ns) / 1e9, 0.0].max : 1.0
      # Cap to deadline to avoid blocking past the test timeout when expiry is nil
      # or far in the future.
      io_timeout = [io_timeout, deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)].min
      io_timeout = 0.0 if io_timeout < 0

      ready = IO.select([sock], nil, nil, io_timeout)
      if ready
        data, _ = sock.recvfrom(2048)
        client.read_pkt(data, local_sockaddr: local_sockaddr, remote_sockaddr: remote_sockaddr)
      else
        client.handle_expiry
      end
    end

    assert_predicate client, :handshake_completed?
  ensure
    sock&.close
  end
end
