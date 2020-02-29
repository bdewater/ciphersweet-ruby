# frozen_string_literal: true

require "openssl"

module Ciphersweet
  module Util
    def self.pack(pieces)
      output = [pieces.length].pack("L<")
      pieces.each do |piece|
        output << [piece.bytesize].pack("Q<")
        output << piece
      end
      output
    end

    def self.and_mask(input, bits, bitwise_left: false)
      bytes = bits >> 3
      if bytes >= input.bytesize
        input = input.ljust(bytes + 1, "\0")
      end
      string = input[0, bytes]

      left_over = bits - (bytes << 3)
      if left_over > 0
        mask = (1 << left_over) - 1
        unless bitwise_left
          mask = (mask & 0xF0) >> 4 | (mask & 0x0F) << 4
          mask = (mask & 0xCC) >> 2 | (mask & 0x33) << 2
          mask = (mask & 0xAA) >> 1 | (mask & 0x55) << 1
        end

        int = input[bytes].unpack1("C")
        string << [int & mask].pack("C")
      end

      string
    end

    if OpenSSL.const_defined?(:KDF) && OpenSSL::KDF.singleton_methods.include?(:hkdf)
      def self.hkdf(ikm, salt:, info:, length: 32, hash: 'sha384')
        OpenSSL::KDF.hkdf(ikm, salt: salt, info: info, length: length, hash: hash)
      end
    else
      def self.hkdf(ikm, salt:, info:, length: 32, hash: 'sha384')
        raise NotImplementedError # FIXME: implement Ruby fallback
      end
    end

    def self.bool_to_chr(bool)
      integer = case bool
        when nil
          0
        when false
          1
        when true
          2
        else
          raise(ArgumentError, "Only nil, false, or true allowed")
      end

      [integer].pack("C")
    end

    def self.chr_to_bool(chr)
      raise(ArgumentError, "String is not 1 byte") if chr.bytesize != 1

      unpacked = chr.unpack1("C")
      case unpacked
        when 0
          nil
        when 1
          false
        when 2
          true
        else
          raise(ArgumentError, "Internal integer is not 0, 1, or 2")
      end
    end

    def self.float_to_string(float)
      [float].pack("d")
    end

    def self.string_to_float(string)
      string.unpack1("d")
    end

    def self.int_to_string(int)
      [int].pack("Q<")
    end

    def self.string_to_int(string)
      string.unpack1("Q<")
    end
  end
end

