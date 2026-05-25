# frozen_string_literal: true

require "test_helper"

class TestQuic < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Quic::VERSION
  end

  def test_library_versions_reports_libressl
    versions = Quic.library_versions
    assert_kind_of String, versions[:ngtcp2]
    assert_match(/LibreSSL/, versions[:openssl])
  end

  def test_connection_client_initializes
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_instance_of Quic::Connection::Client, client
  end

  def test_open_bidi_stream_is_not_implemented
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_raises(NotImplementedError) { client.open_bidi_stream }
  end

  def test_open_uni_stream_is_not_implemented
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_raises(NotImplementedError) { client.open_uni_stream }
  end

  def test_transport_params_default_returns_data_instance
    tp = Quic::TransportParams.default
    assert_kind_of Quic::TransportParams, tp
    assert_kind_of Data, tp
    assert_equal 1_048_576, tp.initial_max_data
    assert_equal 100, tp.initial_max_streams_bidi
    assert_equal 30_000_000_000, tp.max_idle_timeout
  end

  def test_settings_default_returns_data_instance
    settings = Quic::Settings.default
    assert_kind_of Quic::Settings, settings
    assert_kind_of Data, settings
    assert_equal :cubic, settings.cc_algo
    assert_equal 10_000_000_000, settings.handshake_timeout
    assert_equal false, settings.no_pmtud
    assert_equal [], settings.alpn
  end

  def test_transport_params_with_overrides_one_field
    tp = Quic::TransportParams.default.with(initial_max_data: 2**30)
    assert_equal 2**30, tp.initial_max_data
    assert_equal 100, tp.initial_max_streams_bidi
  end

  def test_write_pkt_returns_initial_packet
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    buf = client.write_pkt
    refute_nil buf
    assert_instance_of String, buf
    assert_predicate buf.bytesize, :positive?
    assert_equal Encoding::ASCII_8BIT, buf.encoding
    assert_equal 0xc0, buf.unpack1("C") & 0xc0
  end

  def test_write_pkt_returns_nil_after_draining_initial_flight
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    packets = []
    16.times do
      pkt = client.write_pkt
      break if pkt.nil?
      packets << pkt
    end
    refute_empty packets, "expected at least one Initial packet from the first flight"
    assert_nil client.write_pkt, "expected nil once the Initial flight is drained"
  end

  def test_write_pkt_reuses_provided_binary_buffer
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    buf = String.new(capacity: 1200, encoding: Encoding::BINARY)
    assert_same buf, client.write_pkt(buf)
  end

  def test_write_pkt_raises_on_utf8_buffer
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    buf = String.new("", encoding: Encoding::UTF_8)
    assert_raises(ArgumentError) { client.write_pkt(buf) }
  end

  def test_read_pkt_raises_on_utf8_packet
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    sockaddr = Addrinfo.udp("127.0.0.1", 0).to_sockaddr
    utf8_packet = String.new("\x00", encoding: Encoding::UTF_8)
    assert_raises(ArgumentError) do
      client.read_pkt(utf8_packet, local_sockaddr: sockaddr, remote_sockaddr: sockaddr)
    end
  end

  def test_read_pkt_raises_on_utf8_local_sockaddr
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    sockaddr = Addrinfo.udp("127.0.0.1", 0).to_sockaddr
    binary_packet = String.new("\x00", encoding: Encoding::BINARY)
    utf8_addr = String.new("invalid", encoding: Encoding::UTF_8)
    assert_raises(ArgumentError) do
      client.read_pkt(binary_packet, local_sockaddr: utf8_addr, remote_sockaddr: sockaddr)
    end
  end

  def test_read_pkt_raises_on_utf8_remote_sockaddr
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    sockaddr = Addrinfo.udp("127.0.0.1", 0).to_sockaddr
    binary_packet = String.new("\x00", encoding: Encoding::BINARY)
    utf8_addr = String.new("invalid", encoding: Encoding::UTF_8)
    assert_raises(ArgumentError) do
      client.read_pkt(binary_packet, local_sockaddr: sockaddr, remote_sockaddr: utf8_addr)
    end
  end

  def test_settings_with_alpn_overrides_value
    settings = Quic::Settings.default.with(alpn: ["h3"])
    assert_equal ["h3"], settings.alpn
  end

  def test_alpn_with_h3_does_not_raise_during_open
    settings = Quic::Settings.default.with(alpn: ["h3"])
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443, settings: settings)
    assert_instance_of Quic::Connection::Client, client
  end
end
