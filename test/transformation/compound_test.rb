# frozen_string_literal: true

require "test_helper"
require "ciphersweet/transformation/compound"

class CompoundTest < Minitest::Test
  def setup
    @transformation = Ciphersweet::Transformation::Compound
  end

  def test_call
    [
      [['test'], '["0400000000000000dGVzdA=="]'],
      [['test', 'test2'], '["0400000000000000dGVzdA==","0500000000000000dGVzdDI="]'],
      [{ 'test' => 'test2' }, '{"test":"0500000000000000dGVzdDI="}'],
    ].each do |input, expected_output|
      assert_equal(expected_output, @transformation.call(input))
    end
  end
end
