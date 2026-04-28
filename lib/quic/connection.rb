# frozen_string_literal: true

module Quic
  module Connection
    class Client
      def open_stream
        raise NotImplementedError
      end

      def open_uni_stream
        raise NotImplementedError
      end

      def open_bidi_stream
        raise NotImplementedError
      end
    end
  end

  class Stream
    def initiator
      raise NotImplementedError
    end

    def read
      raise NotImplementedError
    end

    def write
      raise NotImplementedError
    end
  end
end
