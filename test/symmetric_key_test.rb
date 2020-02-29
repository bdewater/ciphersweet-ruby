# frozen_string_literal: true

require "test_helper"
require "ciphersweet/symmetric_key"

class SymmetricKeyTest < Minitest::Test
  def test_inspect_does_not_reveal_key
    variable = "key_material"
    raw_key = "\00" * 32
    symmetric_key = Ciphersweet::SymmetricKey.new(raw_key)

    assert_equal(raw_key, symmetric_key.instance_variable_get("@#{variable}"))
    refute_match(/#{variable}/, symmetric_key.inspect)
  end
end
