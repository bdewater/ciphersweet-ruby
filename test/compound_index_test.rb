# frozen_string_literal: true

require "test_helper"
require "ciphersweet/compound_index"

class CompoundIndexTest < Minitest::Test
  def setup
    @index = Ciphersweet::CompoundIndex.new(
      'ssn_hivstatus',
      columns: ['ssn', 'hivstatus'],
      filter_bits: 32,
      fast_hash: true
    )
    @index.add_transformation('ssn', Ciphersweet::Transformation::LastFourDigits)
  end

  def test_compound_index
    packed = @index.packed({ 'ssn' => '123-45-6789', 'hivstatus' => true })
    assert_equal('{"ssn":"0400000000000000Njc4OQ==","hivstatus":true}', packed)

    packed2 = @index.packed({ 'ssn' => '123-45-6789', 'hivstatus' => false })
    assert_equal('{"ssn":"0400000000000000Njc4OQ==","hivstatus":false}', packed2)
  end
end

