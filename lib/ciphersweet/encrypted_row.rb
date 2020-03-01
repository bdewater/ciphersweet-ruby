# frozen_string_literal: true

require_relative 'encrypted_common'
require_relative 'compound_index'

module Ciphersweet
  class EncryptedRow
    include EncryptedCommon

    COMPOUND_SPECIAL = 'special__compound__indexes'

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

      if @compound_indexes.key?(index_name)
        value[index_name] = calc_compound_index(row, @compound_indexes[index_name])
      end

      value
    end

    def create_compound_index(index_name, columns:, filter_bits: 256, fast_hash: false, hash_config: {})
      index = CompoundIndex.new(
        index_name,
        columns: columns,
        filter_bits: filter_bits,
        fast_hash: fast_hash,
        hash_config: hash_config
      )
      add_compound_index(index)

      index
    end

    def add_compound_index(compound_index)
      @compound_indexes[compound_index.name] = compound_index

      self
    end

    def calc_compound_index(row, compound_index, symmetric_key = nil)
      symmetric_key ||= @engine.blind_index_root_key(@table_name, COMPOUND_SPECIAL)

      backend = @engine.backend
      sub_key = SymmetricKey.new(
        OpenSSL::HMAC.digest(
          'sha256',
          symmetric_key.key_material,
          Util.pack([@table_name, COMPOUND_SPECIAL, compound_index.name])
        )
      )

      plaintext = compound_index.packed(row)

      indexed = if compound_index.fast_hash
        backend.blind_index_fast(plaintext, key: sub_key.key_material, bit_length: compound_index.filter_bits)
      else
        backend.blind_index_slow(
          plaintext,
          key: sub_key.key_material,
          bit_length: compound_index.filter_bits,
          hash_config: compound_index.hash_config
        )
      end

      indexed.unpack1("H*")
    end
  end
end
