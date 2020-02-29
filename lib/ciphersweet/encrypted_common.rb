module Ciphersweet
  module EncryptedCommon
    private

    def convert_from_string(data, type)
      case type
        when :boolean
          Util.chr_to_bool(data)
        when :float
          Util.string_to_float(data)
        when :integer
          Util.string_to_int(data)
        else
          data
      end
    end

    def convert_to_string(data, type)
      case type
        when :boolean
          Util.bool_to_chr(data)
        when :float
          Util.float_to_string(data)
        when :integer
          Util.int_to_string(data)
        else
          data.to_str
      end
    end

    def calc_blind_index(row:, column:, blind_index:, symmetric_key: nil)
      symmetric_key ||= @engine.blind_index_root_key(@table_name, column)

      backend = @engine.backend
      sub_key = SymmetricKey.new(
        OpenSSL::HMAC.digest(
          'sha256',
          symmetric_key.key_material,
          Util.pack([@table_name, column, blind_index.name])
        )
      )

      unless @fields_to_encrypt.key?(column)
        raise(Error, "The field '#{column}' is not defined in this encrypted row")
      end

      field_type = @fields_to_encrypt[column]
      unconverted = row[column]
      plaintext = blind_index.transformed(convert_to_string(unconverted, field_type))

      indexed = if blind_index.fast_hash
        backend.blind_index_fast(plaintext, key: sub_key.key_material, bit_length: blind_index.filter_bits)
      else
        backend.blind_index_slow(
          plaintext,
          key: sub_key.key_material,
          bit_length: blind_index.filter_bits,
          hash_config: blind_index.hash_config
        )
      end

      indexed.unpack1("H*")
    end
  end
end
