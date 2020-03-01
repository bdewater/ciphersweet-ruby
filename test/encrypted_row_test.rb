# frozen_string_literal: true

require "test_helper"
require "ciphersweet/encrypted_row"
require "ciphersweet/engine"
require "ciphersweet/backend/fips_crypto"
require "ciphersweet/key_provider/string"

require "securerandom"

class EncryptedRowTest < Minitest::Test
  def setup
    @engine = Ciphersweet::Engine.new(
      Ciphersweet::KeyProvider::String.new('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'),
      Ciphersweet::Backend::FipsCrypto
    )
  end

  def test_simple_encrypt_fips
    encrypted_row = Ciphersweet::EncryptedRow.new(@engine, "contacts")
    encrypted_row.add_field("message")

    message = "This is a test message: #{SecureRandom.random_bytes(16)}"
    row = { "message" => message }

    ciphertext = encrypted_row.encrypt_row(row)
    assert ciphertext["message"].start_with?("fips:")
    assert_equal(row, encrypted_row.decrypt_row(ciphertext))
  end

  def test_encrypt_aad_fips
    row_without_aad = Ciphersweet::EncryptedRow.new(@engine, "contacts")
    row_without_aad.add_field("message")
    row_with_aad = Ciphersweet::EncryptedRow.new(@engine, "contacts")
    row_with_aad.add_field("message", aad_source_field: "id")

    message = "This is a test message: #{SecureRandom.random_bytes(16)}"
    row = { "id" => 123, "message" => message }

    ciphertext_without_aad = row_without_aad.encrypt_row(row)
    ciphertext_with_aad = row_with_aad.encrypt_row(row)

    assert_raises(Ciphersweet::InvalidCiphertextError, "AAD stripping was permitted") do
      row_with_aad.decrypt_row(ciphertext_without_aad)
    end

    row2 = { "id" => 124, "message" => message }
    ciphertext2_with_aad = row_with_aad.encrypt_row(row2)
    ciphertext2_with_aad['id'] = row['id']
    assert_raises(Ciphersweet::InvalidCiphertextError, "AAD tampering was permitted") do
      row_with_aad.decrypt_row(ciphertext2_with_aad)
    end

    assert_raises(Ciphersweet::InvalidCiphertextError, "AAD was permitted when ciphertext had none") do
      row_without_aad.decrypt_row(ciphertext_with_aad)
    end

    assert_equal(row, row_without_aad.decrypt_row(ciphertext_without_aad))
    assert_equal(row, row_with_aad.decrypt_row(ciphertext_with_aad))
  end

  def test_index_from_partial_info
    row = { "ssn" => "123-45-6789", "hivstatus" => true }
    encrypted_row = example_row(@engine, true)

    blind_index = encrypted_row.blind_index("contact_ssn_last_four", row)
    assert_equal("a88e74ada916ab9b", blind_index["contact_ssn_last_four"])

    compound_index = encrypted_row.blind_index("contact_ssnlast4_hivstatus", row)
    assert_equal("9c3d53214ab71d7f", compound_index["contact_ssnlast4_hivstatus"])
  end

  private

  def example_row(engine, longer = false, fast = false)
    encrypted_row = Ciphersweet::EncryptedRow.new(engine, "contacts")
      .add_field("ssn")
      .add_field("hivstatus", type: :boolean)

    blind_index = Ciphersweet::BlindIndex.new(
      "contact_ssn_last_four",
      transformations: [Ciphersweet::Transformation::LastFourDigits],
      filter_bits: longer ? 64 : 16,
      fast_hash: fast
    )
    encrypted_row.add_blind_index('ssn', blind_index)

    encrypted_row.create_compound_index(
      "contact_ssnlast4_hivstatus",
      columns: ['ssn', 'hivstatus'],
      filter_bits: longer ? 64 : 16,
      fast_hash: fast
    )
    encrypted_row
  end

end
