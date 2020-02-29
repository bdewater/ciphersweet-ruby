# frozen_string_literal: true

require "test_helper"
require "ciphersweet/util"
require "base64"

class UtilTest < Minitest::Test
  def test_pack
    assert_equal("\x00\x00\x00\x00", Ciphersweet::Util.pack([]))
    assert_equal("\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", Ciphersweet::Util.pack(['']))
    assert_equal("\x01\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test", Ciphersweet::Util.pack(['test']))
  end

  def test_and_mask_bitwise_left_false
    testcases = [
      ['ff', 4, 'f0'],
      ['ff', 9, 'ff00'],
      ['ffffffff', 16, 'ffff'],
      ['ffffffff', 17, 'ffff80'],
      ['ffffffff', 18, 'ffffc0'],
      ['ffffffff', 19, 'ffffe0'],
      ['ffffffff', 20, 'fffff0'],
      ['ffffffff', 21, 'fffff8'],
      ['ffffffff', 22, 'fffffc'],
      ['ffffffff', 23, 'fffffe'],
      ['ffffffff', 24, 'ffffff'],
      ['ffffffff', 32, 'ffffffff'],
      ['ffffffff', 64, 'ffffffff00000000'],
      ['55f6778c', 11, '55e0'],
      ['55f6778c', 12, '55f0'],
      ['55f6778c', 13, '55f0'],
      ['55f6778c', 14, '55f4'],
      ['55f6778c', 15, '55f6'],
      ['55f6778c', 16, '55f6'],
      ['55f6778c', 17, '55f600'],
      ['55f6778c', 32, '55f6778c']
    ]

    testcases.each do |input, size, expected|
      assert_equal(
        expected,
        Ciphersweet::Util.and_mask([input].pack('H*'), size, bitwise_left: false).unpack1("H*")
      )
    end
  end

  def test_and_mask_bitwise_left_true
    testcases = [
      ['ff', 4, '0f'],
      ['ff', 9, 'ff00'],
      ['ffffffff', 16, 'ffff'],
      ['ffffffff', 17, 'ffff01'],
      ['ffffffff', 18, 'ffff03'],
      ['ffffffff', 19, 'ffff07'],
      ['ffffffff', 20, 'ffff0f'],
      ['ffffffff', 21, 'ffff1f'],
      ['ffffffff', 22, 'ffff3f'],
      ['ffffffff', 23, 'ffff7f'],
      ['ffffffff', 24, 'ffffff'],
      ['ffffffff', 32, 'ffffffff'],
      ['ffffffff', 64, 'ffffffff00000000'],
      ['55f6778c', 11, '5506'],
      ['55f6778c', 12, '5506'],
      ['55f6778c', 13, '5516'],
      ['55f6778c', 14, '5536'],
      ['55f6778c', 15, '5576'],
      ['55f6778c', 16, '55f6'],
      ['55f6778c', 17, '55f601'],
      ['55f6778c', 32, '55f6778c']
    ]

    testcases.each do |input, size, expected|
      assert_equal(
        expected,
        Ciphersweet::Util.and_mask([input].pack('H*'), size, bitwise_left: true).unpack1("H*")
      )
    end
  end

  def test_bool_to_chr
    assert_equal("\x02", Ciphersweet::Util.bool_to_chr(true))
    assert_equal("\x01", Ciphersweet::Util.bool_to_chr(false))
    assert_equal("\x00", Ciphersweet::Util.bool_to_chr(nil))

    assert_raises(ArgumentError) { Ciphersweet::Util.bool_to_chr(1) }
    assert_raises(ArgumentError) { Ciphersweet::Util.bool_to_chr(0) }
    assert_raises(ArgumentError) { Ciphersweet::Util.bool_to_chr("") }
  end

  def test_chr_to_bool
    assert_equal(true, Ciphersweet::Util.chr_to_bool("\x02"))
    assert_equal(false, Ciphersweet::Util.chr_to_bool("\x01"))
    assert_nil(Ciphersweet::Util.chr_to_bool("\x00"))

    assert_raises(ArgumentError) { Ciphersweet::Util.chr_to_bool("") }
    assert_raises(ArgumentError) { Ciphersweet::Util.chr_to_bool("\x03") }
  end

  def test_float_conversion
    pi = Math::PI
    assert_equal(pi, Ciphersweet::Util.string_to_float(Ciphersweet::Util.float_to_string(pi)))

    random = rand
    assert_equal(random, Ciphersweet::Util.string_to_float(Ciphersweet::Util.float_to_string(random)))
  end

  def test_int_conversion
    max = 2**64 - 1
    assert_equal(max, Ciphersweet::Util.string_to_int(Ciphersweet::Util.int_to_string(max)))

    min = 0
    assert_equal(min, Ciphersweet::Util.string_to_int(Ciphersweet::Util.int_to_string(min)))
  end
end
