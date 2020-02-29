# frozen_string_literal: true

require_relative '../symmetric_key'

module Ciphersweet
  module KeyProvider
    class String
      def initialize(raw_key)
        @root_symmetric_key =
          case raw_key.bytesize
            when 64
              [raw_key].pack("H*")
            when 44
              Base64.urlsafe_decode64(raw_key)
            when 32
              raw_key
            else
              raise(ArgumentError, "Invalid key size")
          end
      end

      def symmetric_key
        @symmetric_key ||= SymmetricKey.new(@root_symmetric_key)
      end

      def inspect
        "#<#{self.class}:0x#{self.__id__.to_s(16)}>"
      end
    end
  end
end
