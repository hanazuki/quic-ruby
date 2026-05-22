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
  end

  def test_transport_params_with_overrides_one_field
    tp = Quic::TransportParams.default.with(initial_max_data: 2**30)
    assert_equal 2**30, tp.initial_max_data
    assert_equal 100, tp.initial_max_streams_bidi
  end
end
