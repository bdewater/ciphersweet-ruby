# frozen_string_literal: true

require "test_helper"
require "ciphersweet/key_provider/string"

class StringTest < Minitest::Test
  def test_inspect_does_not_reveal_key
    variable = "root_symmetric_key"
    raw_key = "\00" * 32
    provider = Ciphersweet::KeyProvider::String.new(raw_key)

    assert_equal(raw_key, provider.instance_variable_get("@#{variable}"))
    refute_match(/#{variable}/, provider.inspect)
  end
end
