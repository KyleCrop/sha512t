require 'minitest/autorun'
require './lib/sha512t'

class Sha512tTest < Minitest::Test
  def test_8_bit
    assert_equal "40",
      Sha512t.hash('000000', 8)

    assert_equal "e6",
      Sha512t.hash('123456', 8)

    assert_equal "1c",
      Sha512t.hash('uvwxyz', 8)
  end

  def test_16_bit
    assert_equal "1893",
      Sha512t.hash('000000', 16)

    assert_equal "ed51",
      Sha512t.hash('123456', 16)

    assert_equal "d4f3",
      Sha512t.hash('uvwxyz', 16)
  end

  def test_24_bit
    assert_equal "c36145",
      Sha512t.hash('000000', 24)

    assert_equal "322e02",
      Sha512t.hash('123456', 24)

    assert_equal "b82f96",
      Sha512t.hash('uvwxyz', 24)
  end

  def test_32_bit
    assert_equal "0fb87900",
      Sha512t.hash('000000', 32)

    assert_equal "b01b3f58",
      Sha512t.hash('123456', 32)

    assert_equal "a7802f1c",
      Sha512t.hash('uvwxyz', 32)
  end

  def test_40_bit
    assert_equal "41561e6db1",
      Sha512t.hash('000000', 40)

    assert_equal "6d92e23336",
      Sha512t.hash('123456', 40)

    assert_equal "12807bfe4b",
      Sha512t.hash('uvwxyz', 40)
  end

  def test_48_bit
    assert_equal "e71453add8ee",
      Sha512t.hash('000000', 48)

    assert_equal "38ebd7973918",
      Sha512t.hash('123456', 48)

    assert_equal "d444c346a738",
      Sha512t.hash('uvwxyz', 48)
  end

  def test_56_bit
    assert_equal "34acd645778a15",
      Sha512t.hash('000000', 56)

    assert_equal "b49acfda08675b",
      Sha512t.hash('123456', 56)

    assert_equal "350690fa30f57b",
      Sha512t.hash('uvwxyz', 56)
  end

  def test_64_bit
    assert_equal "0c8beffa2e95addd",
      Sha512t.hash('000000', 64)

    assert_equal "52261eacb45fe456",
      Sha512t.hash('123456', 64)

    assert_equal "ecfacd8d22e401c6",
      Sha512t.hash('uvwxyz', 64)
  end

  def test_72_bit
    assert_equal "857a80e7286803cf57",
      Sha512t.hash('000000', 72)

    assert_equal "2dc46cba92f277e7ee",
      Sha512t.hash('123456', 72)

    assert_equal "804886d65bb10ba6b9",
      Sha512t.hash('uvwxyz', 72)
  end

  def test_80_bit
    assert_equal "21fb1ba1eb71f834d109",
      Sha512t.hash('000000', 80)

    assert_equal "eeb1e73ed321fb324774",
      Sha512t.hash('123456', 80)

    assert_equal "008184950f9c830e7fdc",
      Sha512t.hash('uvwxyz', 80)
  end

  def test_88_bit
    assert_equal "e382856f8019363544df4e",
      Sha512t.hash('000000', 88)

    assert_equal "0689adfdb5dc251ebee870",
      Sha512t.hash('123456', 88)

    assert_equal "298eaa31c4ecf5f5963d09",
      Sha512t.hash('uvwxyz', 88)
  end

  def test_96_bit
    assert_equal "189135861b522f62756400b2",
      Sha512t.hash('000000', 96)

    assert_equal "7faeba0512326c125ddc89f7",
      Sha512t.hash('123456', 96)

    assert_equal "555e97a5903df06d2f818a19",
      Sha512t.hash('uvwxyz', 96)
  end

  def test_104_bit
    assert_equal "b7a5c6dbfad0d3c9d77560b9ea",
      Sha512t.hash('000000', 104)

    assert_equal "7fa9d643798cb0605eb8b07311",
      Sha512t.hash('123456', 104)

    assert_equal "a3d0a1dce670fe231c80a2fbfb",
      Sha512t.hash('uvwxyz', 104)
  end

  def test_112_bit
    assert_equal "b61089a3983050f4fbf8687d6fbf",
      Sha512t.hash('000000', 112)

    assert_equal "c415857e3a4d15cac1439003f386",
      Sha512t.hash('123456', 112)

    assert_equal "36f690af14514051741107661876",
      Sha512t.hash('uvwxyz', 112)
  end

  def test_120_bit
    assert_equal "44e707b93fd9187f8d9a80feb80e23",
      Sha512t.hash('000000', 120)

    assert_equal "c323f7a92a5dfbd789ee718c251838",
      Sha512t.hash('123456', 120)

    assert_equal "f376b5124cda7e41f8ac320945265c",
      Sha512t.hash('uvwxyz', 120)
  end

  def test_128_bit
    assert_equal "caf545b7cdbea1ea43b3b37584d31c7e",
      Sha512t.hash('000000', 128)

    assert_equal "f0ebb85afa22413c242e0e27c7ed0550",
      Sha512t.hash('123456', 128)

    assert_equal "7f5e84cb23e0842380b4f20b2f185454",
      Sha512t.hash('uvwxyz', 128)
  end
end