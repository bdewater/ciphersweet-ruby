# frozen_string_literal: true

module Ciphersweet
  module Transformation
    module LastFourDigits
      def self.call(string)
        string
          .gsub(/[^0-9]/, "")
          .rjust(4, "0")
          .slice(-4, 4)
      end
    end
  end
end
