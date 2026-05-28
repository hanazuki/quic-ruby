# frozen_string_literal: true

module Quic
  # Quic::Stream is defined in the C extension (ext/quic/stream.c); this file
  # reopens it to add the bits that are easier to express in Ruby:
  # #initiator (a tiny lookup over @id) and the blocking #read which wraps
  # the C #read_nonblock with an internal Client#pump_until loop.
  class Stream
    INITIATORS = %i[client_bidi server_bidi client_uni server_uni].freeze

    attr_reader :id
    alias_method :stream_id, :id

    # RFC 9000 §2.1: the lowest two bits of stream_id encode the initiator
    # (LSB) and direction (bit 1).
    def initiator
      INITIATORS[@id & 0b11]
    end

    # IO#read-compatible blocking read. Requires the parent Client to have
    # been #bind'ed to a socket (raised via Client#pump_once otherwise).
    #
    #   read(length): block until at least 1 byte is available or EOF,
    #                 return up to `length` bytes, return nil at EOF.
    #   read(nil):    block until EOF, return everything that was received
    #                 (an empty String if nothing arrived before FIN).
    def read(length = nil)
      if length.nil?
        @client.pump_until { eof? }
        out = +""
        out.force_encoding(Encoding::BINARY)
        until eof?
          # Should not happen given pump_until's predicate, but defensive.
          out << read_nonblock(4096)
        end
        # Drain anything that arrived after the predicate was last evaluated.
        loop do
          out << read_nonblock(4096)
        rescue Quic::Error::WaitReadable, EOFError
          break
        end
        out
      else
        @client.pump_until { @recv_buffer.bytesize > 0 || @fin_received }
        begin
          read_nonblock(length)
        rescue EOFError
          nil
        end
      end
    end
  end
end
