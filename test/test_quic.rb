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
    client = Quic::Connection::Client.new(host: "example.com", port: 443)
    assert_instance_of Quic::Connection::Client, client
  end

  def test_open_stream_is_not_implemented
    client = Quic::Connection::Client.new(host: "example.com", port: 443)
    assert_raises(NotImplementedError) { client.open_stream }
  end
end
