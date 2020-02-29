# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'securerandom'

require_relative '../refinements/fixed_length_secure_compare'
require_relative '../errors'
require_relative '../util'

module Ciphersweet
  module Backend
    module FipsCrypto
      using FixedLengthSecureCompare

      MAGIC_HEADER = "fips:"

      MAC_SIZE = 48
      SALT_SIZE = 32
      NONCE_SIZE = 16

      ENCRYPTION_KEY_INFO = 'AES-256-CTR'
      MAC_KEY_INFO = 'HMAC-SHA-384'

      def self.encrypt(plaintext, symmetric_key:, aad: '')
        hkdf_salt = SecureRandom.random_bytes(SALT_SIZE)
        ctr_nonce = SecureRandom.random_bytes(NONCE_SIZE)

        encryption_key = Util.hkdf(symmetric_key.key_material, salt: hkdf_salt, info: ENCRYPTION_KEY_INFO)
        mac_key = Util.hkdf(symmetric_key.key_material, salt: hkdf_salt, info: MAC_KEY_INFO)

        cipher = aes(:encrypt, encryption_key, ctr_nonce)
        ciphertext = "#{cipher.update(plaintext)}#{cipher.final}"
        mac = hmac(mac_key, "#{Util.pack([MAGIC_HEADER, hkdf_salt, ctr_nonce, ciphertext])}#{aad}")

        "#{MAGIC_HEADER}#{Base64.urlsafe_encode64("#{hkdf_salt}#{ctr_nonce}#{mac}#{ciphertext}")}"
      end

      def self.decrypt(data, symmetric_key:, aad: '')
        header = data[0, 5]
        unless OpenSSL.fixed_length_secure_compare(MAGIC_HEADER, header)
          raise(InvalidCiphertextError, "Invalid ciphertext header")
        end

        decoded = Base64.urlsafe_decode64(data[5..-1])
        raise(InvalidCiphertextError, "Message is too short") if decoded.bytesize < MAC_SIZE + NONCE_SIZE + SALT_SIZE

        hkdf_salt = decoded[0, SALT_SIZE]
        ctr_nonce = decoded[SALT_SIZE, NONCE_SIZE]
        mac = decoded[SALT_SIZE + NONCE_SIZE, MAC_SIZE]
        ciphertext = decoded[SALT_SIZE + NONCE_SIZE + MAC_SIZE..-1]

        encryption_key = Util.hkdf(symmetric_key.key_material, salt: hkdf_salt, info: ENCRYPTION_KEY_INFO)
        mac_key = Util.hkdf(symmetric_key.key_material, salt: hkdf_salt, info: MAC_KEY_INFO)

        expected_mac = hmac(mac_key, "#{Util.pack([MAGIC_HEADER, hkdf_salt, ctr_nonce, ciphertext])}#{aad}")
        unless OpenSSL.fixed_length_secure_compare(expected_mac, mac)
          raise(InvalidCiphertextError, "Invalid MAC")
        end

        cipher = aes(:decrypt, encryption_key, ctr_nonce)
        "#{cipher.update(ciphertext)}#{cipher.final}"
      end

      def self.blind_index_fast(plaintext, key:, bit_length: 256)
        output = OpenSSL::KDF.pbkdf2_hmac(
          plaintext,
          salt: key,
          iterations: 1,
          length: bit_length >> 3,
          hash: 'sha384'
        )
        Util.and_mask(output, bit_length)
      end

      def self.blind_index_slow(plaintext, key:, bit_length: 256, hash_config: {})
        output = OpenSSL::KDF.pbkdf2_hmac(
          plaintext,
          salt: key,
          iterations: hash_config[:iterations].to_i.clamp(50_000, Float::INFINITY),
          length: bit_length >> 3,
          hash: 'sha384'
        )
        Util.and_mask(output, bit_length)
      end

      def self.aes(mode, key, nonce)
        cipher = OpenSSL::Cipher.new('AES-256-CTR')
        cipher.send(mode)
        cipher.key = key
        cipher.iv = nonce
        cipher
      end
      private_class_method(:aes)

      def self.hmac(key, data)
        OpenSSL::HMAC.digest('sha384', key, data)
      end
      private_class_method(:hmac)
    end
  end
end
