# frozen_string_literal: true

require "test_helper"
require "ciphersweet/transformation/lowercase"

class LowercaseTest < Minitest::Test
  def setup
    @transformation = Ciphersweet::Transformation::Lowercase
  end

  def test_call
    [
      ['APPLE', 'apple'],
      ["This is a Test String with whitespace\n", "this is a test string with whitespace\n"]
    ].each do |input, expected_output|
      assert_equal(expected_output, @transformation.call(input))
    end
  end
end
