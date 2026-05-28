# frozen_string_literal: true

# Stream API demo: open a bidirectional stream, write a small payload with
# FIN, then block on Stream#read until the peer echoes the bytes back and
# closes its side. Requires a local QUIC echo server (default: 127.0.0.1:4433
# with ALPN "perf"); ngtcp2 ships an examples/server binary that does this
# when built with --enable-examples.
#
# Override the target via env vars:
#   QUIC_ECHO_HOST  (default 127.0.0.1)
#   QUIC_ECHO_PORT  (default 4433)
#   QUIC_ECHO_ALPN  (default perf)
#
# Run with: bundle exec ruby examples/echo_demo.rb

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "quic"
require "socket"

TARGET_HOST = ENV.fetch("QUIC_ECHO_HOST", "127.0.0.1")
TARGET_PORT = Integer(ENV.fetch("QUIC_ECHO_PORT", "4433"))
TARGET_ALPN = ENV.fetch("QUIC_ECHO_ALPN", "perf")

addr = Addrinfo.getaddrinfo(TARGET_HOST, TARGET_PORT, Socket::AF_INET, Socket::SOCK_DGRAM).first
sock = UDPSocket.new
sock.connect(addr.ip_address, addr.ip_port)

settings = Quic::Settings.default.with(alpn: [TARGET_ALPN])
client = Quic::Connection::Client._open(
  local_sockaddr: Addrinfo.udp("0.0.0.0", 0).to_sockaddr,
  remote_sockaddr: addr.to_sockaddr,
  server_name: TARGET_HOST,
  transport_params: Quic::TransportParams.default,
  settings: settings
)
client.bind(sock).run

stream = client.open_bidi_stream
puts "opened stream #{stream.id} (#{stream.initiator})"

payload = "hello quic stream\n"
stream.write(payload, fin: true)
puts "sent #{payload.bytesize} bytes + FIN"

response = stream.read
puts "received #{response.bytesize} bytes:"
puts response

sock.close
