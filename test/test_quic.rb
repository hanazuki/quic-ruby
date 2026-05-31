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

  def test_open_bidi_stream_raises_before_handshake
    # Without a completed handshake the server's transport parameters have
    # not arrived, so ngtcp2 reports NGTCP2_ERR_STREAM_ID_BLOCKED. This is
    # mapped to Quic::Error::Unknown via the default switch arm.
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    err = assert_raises(Quic::Error) { client.open_bidi_stream }
    assert_match(/STREAM_ID_BLOCKED/, err.message)
  end

  def test_open_uni_stream_raises_before_handshake
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    err = assert_raises(Quic::Error) { client.open_uni_stream }
    assert_match(/STREAM_ID_BLOCKED/, err.message)
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

  def test_handshake_completed_is_false_initially
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_equal false, client.handshake_completed?
  end

  def test_in_closing_period_is_false_initially
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_equal false, client.in_closing_period?
  end

  def test_in_draining_period_is_false_initially
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_equal false, client.in_draining_period?
  end

  def test_expiry_returns_integer_after_init
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    expiry = client.expiry
    assert_kind_of Integer, expiry
    assert_predicate expiry, :positive?
  end

  def test_handle_expiry_does_not_raise_after_init
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_nil client.handle_expiry
  end

  def test_alpn_with_h3_does_not_raise_during_open
    settings = Quic::Settings.default.with(alpn: ["h3"])
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443, settings: settings)
    assert_instance_of Quic::Connection::Client, client
  end

  # Build a bare Quic::Stream for tests that exercise the in-Ruby state
  # machine (initiator lookup, recv_buffer mutation, pending_chunks queue)
  # without needing a completed handshake. The C-side quic_stream_t is
  # zero-initialized by the alloc func; we only have to wire the Ruby ivars.
  def build_stream(id:, client: nil)
    Quic::Stream.allocate.tap do |s|
      s.instance_variable_set(:@id, id)
      s.instance_variable_set(:@client, client)
      s.instance_variable_set(:@pending_chunks, [])
      s.instance_variable_set(:@recv_buffer, String.new(encoding: Encoding::BINARY))
    end
  end

  def test_stream_id_alias
    s = build_stream(id: 4)
    assert_equal 4, s.id
    assert_equal 4, s.stream_id
  end

  def test_stream_initiator_table
    assert_equal :client_bidi, build_stream(id: 0).initiator
    assert_equal :server_bidi, build_stream(id: 1).initiator
    assert_equal :client_uni, build_stream(id: 2).initiator
    assert_equal :server_uni, build_stream(id: 3).initiator
    # Same pattern repeats for higher IDs.
    assert_equal :client_bidi, build_stream(id: 4).initiator
  end

  def test_stream_eof_is_false_initially
    refute_predicate build_stream(id: 0), :eof?
  end

  def test_stream_read_nonblock_raises_wait_readable_when_empty
    err = assert_raises(Quic::Error::WaitReadable) { build_stream(id: 0).read_nonblock(1024) }
    assert_kind_of IO::WaitReadable, err
  end

  def test_stream_write_returns_bytesize_and_queues_chunk
    s = build_stream(id: 0)
    assert_equal 5, s.write("hello")
    chunks = s.instance_variable_get(:@pending_chunks)
    assert_equal 1, chunks.length
    assert_equal "hello", chunks.first
    assert_equal Encoding::BINARY, chunks.first.encoding
  end

  def test_stream_write_with_fin_sets_state
    s = build_stream(id: 0)
    s.write("bye", fin: true)
    # Once FIN is queued, further writes raise StreamClosed.
    assert_raises(Quic::Error::StreamClosed) { s.write("more") }
  end

  def test_client_run_raises_not_bound_without_bind
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_raises(Quic::Error::NotBound) { client.run }
  end

  def test_client_bind_returns_self_and_records_socket
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    sock = UDPSocket.new
    begin
      assert_same client, client.bind(sock)
      assert_same sock, client.bound_socket
    ensure
      sock.close
    end
  end

  # Build a Stream whose @client is a real (handshake-incomplete) Client so
  # the flow control window check kicks in. ngtcp2 reports
  # max_stream_data_left = 0 for unopened streams, which is exactly the
  # condition Stream#write_nonblock should turn into Quic::Error::WaitWritable.
  def test_stream_write_nonblock_raises_wait_writable_when_window_zero
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    stream = Quic::Stream.allocate
    stream.instance_variable_set(:@id, 0)
    stream.instance_variable_set(:@client, client)
    stream.instance_variable_set(:@pending_chunks, [])
    stream.instance_variable_set(:@recv_buffer, String.new(encoding: Encoding::BINARY))

    err = assert_raises(Quic::Error::WaitWritable) { stream.write_nonblock("x") }
    assert_kind_of IO::WaitWritable, err
  end

  # Stream#write blocks by repeatedly calling @client.pump_once, which in
  # turn raises Quic::Error::NotBound when no socket has been bound. We
  # surface that error verbatim from #write.
  def test_stream_write_raises_not_bound_when_client_not_bound
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    stream = Quic::Stream.allocate
    stream.instance_variable_set(:@id, 0)
    stream.instance_variable_set(:@client, client)
    stream.instance_variable_set(:@pending_chunks, [])
    stream.instance_variable_set(:@recv_buffer, String.new(encoding: Encoding::BINARY))

    assert_raises(Quic::Error::NotBound) { stream.write("x") }
  end

  def test_client_close_raises_not_bound_without_bind
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_raises(Quic::Error::NotBound) { client.close }
  end

  # Before the handshake completes, ngtcp2_conn_write_connection_close
  # returns NGTCP2_ERR_INVALID_STATE. The spec treats this as best-effort,
  # so #close silently no-ops (returns nil without raising). The full
  # handshake -> close -> in_closing_period? path is exercised by the
  # EXTERNAL=1 cloudflare e2e test.
  def test_client_close_returns_nil_when_bound
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    sock = UDPSocket.new
    sock.connect("127.0.0.1", 443)
    client.bind(sock)
    begin
      assert_nil client.close
    ensure
      sock.close
    end
  end

  def test_client_close_accepts_error_code_and_reason_kwargs
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    sock = UDPSocket.new
    sock.connect("127.0.0.1", 443)
    client.bind(sock)
    begin
      assert_nil client.close(error_code: 42, reason: "bye")
    ensure
      sock.close
    end
  end

  def test_client_close_is_noop_when_already_closed
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    sock = UDPSocket.new
    sock.connect("127.0.0.1", 443)
    client.bind(sock)
    begin
      client.close
      # Second close should not emit another packet nor raise.
      assert_nil client.close
    ensure
      sock.close
    end
  end

  def test_client_remote_address_is_addrinfo
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_kind_of Addrinfo, client.remote_address
    assert_equal "127.0.0.1", client.remote_address.ip_address
    assert_equal 443, client.remote_address.ip_port
  end

  def test_client_address_family_inet_pins_ipv4
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443, address_family: :inet)
    assert_equal Socket::AF_INET, client.remote_address.afamily
  end

  def test_client_address_family_inet6_pins_ipv6
    client = Quic::Connection::Client.new(host: "::1", port: 443, address_family: :inet6)
    assert_equal Socket::AF_INET6, client.remote_address.afamily
  end

  def test_client_address_family_nil_is_phase4_compatible
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443, address_family: nil)
    assert_instance_of Quic::Connection::Client, client
    assert_equal Socket::AF_INET, client.remote_address.afamily
  end

  def test_client_address_family_unknown_raises_argument_error
    assert_raises(ArgumentError) do
      Quic::Connection::Client.new(host: "127.0.0.1", port: 443, address_family: :bogus)
    end
  end

  # The Client TypedData holds a VALUE back-reference (owner) that ngtcp2
  # callbacks resolve through. quic_client_compact follows it via
  # rb_gc_location so GC.compact does not leave it stale. Build a live
  # Client with a couple of bare streams registered, force compaction with
  # reference verification, then confirm the object is still coherent.
  def test_client_survives_gc_compaction
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    streams = client.instance_variable_get(:@streams)
    streams[0] = build_stream(id: 0, client: client)
    streams[1] = build_stream(id: 1, client: client)

    GC.verify_compaction_references(expand_heap: true, toward: :empty)

    assert_equal false, client.handshake_completed?
    assert_kind_of Integer, client.expiry
    assert_same client, streams[0].instance_variable_get(:@client)
  end

  # A bare Stream (@client == nil) escapes the ngtcp2 call and only flips
  # the internal reset flag, mirroring #write's bare-Stream escape. After
  # #reset, the existing quic_stream_enqueue guard makes #write raise
  # Quic::Error::StreamClosed.
  def test_stream_reset_marks_write_side_closed
    s = build_stream(id: 0)
    assert_nil s.reset
    assert_raises(Quic::Error::StreamClosed) { s.write("data") }
  end

  def test_stream_reset_accepts_error_code
    s = build_stream(id: 0)
    assert_nil s.reset(42)
    assert_raises(Quic::Error::StreamClosed) { s.write_nonblock("data") }
  end

  def test_stream_reset_is_idempotent
    s = build_stream(id: 0)
    s.reset
    # Second reset must not raise.
    assert_nil s.reset
  end

  def test_accept_stream_nonblock_raises_wait_readable_when_empty
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    err = assert_raises(Quic::Error::WaitReadable) { client.accept_stream_nonblock }
    assert_kind_of IO::WaitReadable, err
  end

  def test_accept_stream_nonblock_returns_queued_stream
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    queue = client.instance_variable_get(:@accept_queue)
    server_stream = build_stream(id: 1, client: client)
    queue.push(server_stream)

    assert_same server_stream, client.accept_stream_nonblock
    # Queue is now drained.
    assert_raises(Quic::Error::WaitReadable) { client.accept_stream_nonblock }
  end

  def test_accept_stream_with_zero_timeout_returns_nil_when_empty
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_nil client.accept_stream(timeout: 0)
  end

  def test_accept_stream_returns_queued_stream_without_pumping
    client = Quic::Connection::Client.new(host: "127.0.0.1", port: 443)
    queue = client.instance_variable_get(:@accept_queue)
    server_stream = build_stream(id: 1, client: client)
    queue.push(server_stream)

    # Queue non-empty: returns immediately, no #bind / pump needed.
    assert_same server_stream, client.accept_stream(timeout: nil)
  end
end
