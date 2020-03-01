# frozen_string_literal: true

module Ciphersweet
  class CompoundIndex
    attr_reader :name, :filter_bits, :fast_hash, :hash_config

    def initialize(name, columns:, filter_bits: 256, fast_hash: false, hash_config: {})
      @name = name
      @columns = columns
      @filter_bits = filter_bits
      @fast_hash = fast_hash
      @hash_config = hash_config
      @column_transformations = Hash.new { |hash, key| hash[key] = [] }
    end

    def add_transformation(column, transformation)
      @column_transformations[column] << transformation

      self
    end

    def packed(row)
      pieces = {}

      @columns.each do |column|
        return unless row.key?(column)

        piece = row[column]
        if @column_transformations.key?(column)
          @column_transformations.each do |_column, transformations|
            piece = transformations.reduce(piece) do |result, transformation|
              transformation.call(result)
            end
          end
        end

        pieces[column] = piece
      end

      # TODO: row transforms

      if pieces.is_a?(String)
        pieces
      else
        Transformation::Compound.call(pieces)
      end
    end
  end
end
