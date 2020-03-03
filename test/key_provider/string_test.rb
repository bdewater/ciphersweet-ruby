# frozen_string_literal: true

require "test_helper"
require "ciphersweet/key_provider/string"

class StringTest < Minitest::Test
  def test_accepts_various_encoded_formats
    {
      hex: "4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc",
      urlsafe_base64: "ThxE-HtM3yGAh2KXCzVokdsYCp3ZhQ57ryp5_zq4ovw=",
      base64: "ThxE+HtM3yGAh2KXCzVokdsYCp3ZhQ57ryp5/zq4ovw=",
      binary: ["4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc"].pack("H*"),
    }.each do |format, string|
      assert_kind_of(
        Ciphersweet::SymmetricKey,
        Ciphersweet::KeyProvider::String.new(string).symmetric_key,
        "failed to decode #{format}"
      )
    end
  end

  def test_does_not_accept_short_strings
    assert_raises(ArgumentError) do
      Ciphersweet::KeyProvider::String.new("string")
    end
  end

  def test_does_not_accept_nonbinary_encoded_strings
    assert_raises(ArgumentError) do
      Ciphersweet::KeyProvider::String.new("a" * 32)
    end
  end
end
