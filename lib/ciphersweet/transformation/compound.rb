# frozen_string_literal: true

require "base64"
require "json"

module Ciphersweet
  module Transformation
    module Compound
      def self.call(input)
        JSON.generate(process(input))
      end

      def self.pack_string(string)
        length = [string.bytesize].pack("Q<").unpack1("H*")

        "#{length}#{Base64.urlsafe_encode64(string)}"
      end

      def self.process(input, layer = 0)
        raise Error, "Too much recursion" if layer > 255

        case input
          when Array
            input.map { |value| process(value, layer + 1) }
          when Hash
            input.transform_values { |value| process(value, layer + 1) }
          when Numeric
            input.to_s
          when String
            pack_string(input)
          else
            input
        end
      end
    end
  end
end
