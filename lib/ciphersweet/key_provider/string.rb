# frozen_string_literal: true

require_relative '../symmetric_key'

module Ciphersweet
  module KeyProvider
    class String
      attr_reader :symmetric_key

      def initialize(raw_key)
        size = raw_key.bytesize
        @symmetric_key = SymmetricKey.new(
          if size == 64 && raw_key.match?(/\A[[:xdigit:]]*\z/)
            [raw_key].pack("H*")
          elsif size == 44 && raw_key.match?(/\A[[[:alnum:]]-_=]*\z/)
            Base64.urlsafe_decode64(raw_key)
          elsif size == 44 && raw_key.match?(/\A[[[:alnum:]]+\/=]*\z/)
            Base64.strict_decode64(raw_key)
          elsif size == 32 && raw_key.encoding == Encoding::BINARY
            raw_key
          else
            raise(ArgumentError, "Invalid key size")
          end
        )
      end
    end
  end
end
