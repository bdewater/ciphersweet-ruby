# frozen_string_literal: true

require_relative 'util'

module Ciphersweet
  class Engine
    DS_BIDX = ("\x7E" * 32).freeze
    DS_FENC = ("\xB4" * 32).freeze

    attr_reader :backend

    def initialize(key_provider, backend)
      @key_provider = key_provider
      @backend = backend
    end

    def blind_index_root_key(table_name, field_name)
      SymmetricKey.new(
        Util.hkdf(@key_provider.symmetric_key.key_material, salt: table_name, info: "#{DS_BIDX}#{field_name}")
      )
    end

    def field_symmetric_key(table_name, field_name)
      SymmetricKey.new(
        Util.hkdf(@key_provider.symmetric_key.key_material, salt: table_name, info: "#{DS_FENC}#{field_name}")
      )
    end
  end
end
