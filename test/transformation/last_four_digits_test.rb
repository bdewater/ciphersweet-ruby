# frozen_string_literal: true

require "test_helper"
require "ciphersweet/transformation/last_four_digits"

class LastFourDigitsTest < Minitest::Test
  def setup
    @transformation = Ciphersweet::Transformation::LastFourDigits
  end

  def test_call
    [
      ['apple', '0000'],
      ['1', '0001'],
      ['12', '0012'],
      ['123', '0123'],
      ['1234', '1234'],
      ['12345', '2345'],
      ['123456', '3456'],
      ['123-456-7890', '7890']
    ].each do |input, expected_output|
      assert_equal(expected_output, @transformation.call(input))
    end
  end
end
