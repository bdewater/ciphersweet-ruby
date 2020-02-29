# frozen_string_literal: true

module Ciphersweet
  class SymmetricKey
    attr_reader :key_material

    def initialize(key_material)
      @key_material = key_material
      freeze
    end

    def inspect
      "#<#{self.class}:0x#{self.__id__.to_s(16)}>"
    end
  end
end
