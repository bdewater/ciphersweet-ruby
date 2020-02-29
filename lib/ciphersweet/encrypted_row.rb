# frozen_string_literal: true

require_relative 'encrypted_common'

module Ciphersweet
  class EncryptedRow
    include EncryptedCommon

    def initialize(engine, table_name)
      @engine = engine
      @table_name = table_name

      @fields_to_encrypt = {}
      @aad_source_field = {}
      @blind_indexes = Hash.new { |hash, key| hash[key] = {} }
      @compound_indexes = Hash.new { |hash, key| hash[key] = {} }
    end

    def add_field(field_name, aad_source_field: nil, type: :text)
      @fields_to_encrypt[field_name] = type
      if aad_source_field
        @aad_source_field[field_name] = aad_source_field
      end

      self
    end

    def encrypt_row(row)
      value = row.dup
      backend = @engine.backend

      @fields_to_encrypt.each do |field, type|
        key = @engine.field_symmetric_key(@table_name, field)

        ciphertext = if @aad_source_field[field] && row.key?(@aad_source_field[field])
          backend.encrypt(row[field], symmetric_key: key, aad: row[@aad_source_field[field]])
        else
          backend.encrypt(row[field], symmetric_key: key)
        end

        value[field] = convert_to_string(ciphertext, type)
      end

      value
    end

    def decrypt_row(row)
      value = row.dup
      backend = @engine.backend

      @fields_to_encrypt.each do |field, type|
        key = @engine.field_symmetric_key(@table_name, field)

        plaintext = if @aad_source_field[field] && row.key?(@aad_source_field[field])
          backend.decrypt(row[field], symmetric_key: key, aad: row[@aad_source_field[field]])
        else
          backend.decrypt(row[field], symmetric_key: key)
        end

        value[field] = convert_from_string(plaintext, type)
      end

      value
    end

    def add_blind_index(column, blind_index)
      @blind_indexes[column][blind_index.name] = blind_index

      self
    end

    def blind_index(index_name, row)
      value = {}

      @blind_indexes.each do |column, blind_indexes|
        if blind_indexes.key?(index_name)
          value[index_name] = calc_blind_index(row: row, column: column, blind_index: blind_indexes[index_name])
        end
      end

      value
    end
  end
end
