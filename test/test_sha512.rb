require 'minitest/autorun'
require './lib/sha512'

class Sha512Test < Minitest::Test
  def test_hash
    assert_equal "64fcc6f6bc7a815041b4db51f00f4bea8e51c13b27f422da0a8522c94641c7e483c3f17b28d0a59add0c8a44a4e4fc1dd3a9ea48bad8cf5b707ac0f44a5f3536",
      Sha512.hash('000000')

    assert_equal "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413",
      Sha512.hash('123456')

    assert_equal "e32ef19623e8ed9d267f657a81944b3d07adbb768518068e88435745564e8d4150a0a703be2a7d88b61e3d390c2bb97e2d4c311fdc69d6b1267f05f59aa920e7",
      Sha512.hash('abcdef')

    assert_equal "3a28e294a3cc75a0e6808489aab55efec88e47f6be48cd6459911c159fcd2474463904c11c0733f2a1accd0896f69bf170f371f1c91b5c472d01ff3a13a9a75f",
      Sha512.hash('uvwxyz')
  end
end