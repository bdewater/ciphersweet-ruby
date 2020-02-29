# frozen_string_literal: true

module Ciphersweet
  module Transformation
    module Lowercase
      def self.call(string)
        string.downcase
      end
    end
  end
end
