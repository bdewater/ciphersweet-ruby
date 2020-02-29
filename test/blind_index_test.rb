# frozen_string_literal: true

require "test_helper"
require "ciphersweet/blind_index"

class UtilTest < Minitest::Test
  def test_blind_index
    assert_equal("\x00\x00\x00\x00", Ciphersweet::Util.pack([]))

  end
end
