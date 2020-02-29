# frozen_string_literal: true

module Ciphersweet
  class BlindIndex
    attr_reader :name, :filter_bits, :fast_hash, :hash_config

    def initialize(name, transformations = [], filter_bits = 256, fast_hash = false, hash_config = {})
      @name = name
      @transformations = transformations
      @filter_bits = filter_bits
      @fast_hash = fast_hash
      @hash_config = hash_config
    end

    def add_transformation(transformation)
      @transformations << transformation

      self
    end

    def transformed(input)
      @transformations.reduce(input) do |result, transformation|
        transformation.call(result)
      end
    end
  end
end
