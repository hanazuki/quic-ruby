# frozen_string_literal: true

# Sample script: drive a real QUIC + TLS 1.3 handshake against a public
# HTTP/3 server (cloudflare-quic.com:443) using Client#bind + Client#run.
#
# Why _open instead of Client.new: Client.new resolves the hostname via
# Addrinfo.udp, and UDPSocket#connect resolves it independently. Cloudflare
# returns multiple A/AAAA records, so the two resolutions can disagree
# and ngtcp2 then drops every reply with "ignore packet from unknown path".
# Pre-resolving once to a single IPv4 sockaddr and feeding it to both
# _open and the socket avoids this.
#
# Run with: bundle exec ruby examples/handshake_demo.rb

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "quic"
require "socket"

TARGET_HOST = "cloudflare-quic.com"
TARGET_PORT = 443

addr = Addrinfo.getaddrinfo(TARGET_HOST, TARGET_PORT, Socket::AF_INET, Socket::SOCK_DGRAM).first
sock = UDPSocket.new
sock.connect(addr.ip_address, addr.ip_port)

settings = Quic::Settings.default.with(alpn: ["h3"])
client = Quic::Connection::Client._open(
  local_sockaddr: Addrinfo.udp("0.0.0.0", 0).to_sockaddr,
  remote_sockaddr: addr.to_sockaddr,
  server_name: TARGET_HOST,
  transport_params: Quic::TransportParams.default,
  settings: settings
)

puts "ngtcp2: #{Quic.library_versions[:ngtcp2]}"
puts "TLS:    #{Quic.library_versions[:openssl]}"
puts "Target: #{TARGET_HOST} (#{addr.ip_address}:#{addr.ip_port})"
puts

t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
client.bind(sock).run
elapsed_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round(1)

puts "handshake_completed? #{client.handshake_completed?} (#{elapsed_ms}ms)"
sock.close
