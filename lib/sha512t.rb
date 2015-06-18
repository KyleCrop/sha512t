# FIPS PUB 180-4 SHA512/t hashing
# written by Frederic Walch

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require_relative 'sha512'

class Sha512t
  def digest(t)
    if t < 0
      abort("bitLength cannot be less than 0.")
    end
    
    if t > 511
      abort("bitLength cannot be >= 512.")
    end

    if t % 8 != 0
      abort("bitLength needs to be a multiple of 8.")
    end

    if t == 384
      abort("bitLength cannot be 384 use SHA384 instead.")
    end

    if t == 256
      abort("bitLength cannot be 256 use SHA256 instead.")
    end

    if t == 512
      abort("bitLength cannot be 512 use SHA512 instead.")
    end
  end

  def generate_iv(iv)
    generated_iv = []
    for i in 0..7
      generated_iv.push(iv[i*16..(i*16)+15].to_i(16))
    end
    return generated_iv
  end

  def sha512t_truncate(hash, t)
    hash = hash.to_i(16).to_s(2)
    if hash.length < 512
      hash = "0" * (512 - hash.length) + hash
    end
    hash = hash[0..t-1].to_i(2).to_s(16)

    if hash.length < t/4
      hash = "0" * (t/4 - hash.length) + hash
    end
    return hash
  end

  def self.hash(message, t)
    # SHA512/t initial hash value from FIPS-180
    sha512t_initial_iv = [  0x6a09e667f3bcc908 ^ 0xa5a5a5a5a5a5a5a5,
                            0xbb67ae8584caa73b ^ 0xa5a5a5a5a5a5a5a5,
                            0x3c6ef372fe94f82b ^ 0xa5a5a5a5a5a5a5a5,
                            0xa54ff53a5f1d36f1 ^ 0xa5a5a5a5a5a5a5a5,
                            0x510e527fade682d1 ^ 0xa5a5a5a5a5a5a5a5,
                            0x9b05688c2b3e6c1f ^ 0xa5a5a5a5a5a5a5a5,
                            0x1f83d9abfb41bd6b ^ 0xa5a5a5a5a5a5a5a5,
                            0x5be0cd19137e2179 ^ 0xa5a5a5a5a5a5a5a5 ]

    Sha512t.new.digest(t)
    # Generate SHA-512/t IV
    preprocessed_massage = Sha512.new.preprocessing("SHA-512/#{t}")
    computed_iv =  Sha512.new.hash_computation(preprocessed_massage, sha512t_initial_iv)
    sha512t_iv = Sha512t.new.generate_iv(computed_iv)

    # Hash with SHA-512/t IV and truncate t-bits
    preprocessed_massage = Sha512.new.preprocessing(message)
    sha512t_untruncated = Sha512.new.hash_computation(preprocessed_massage, sha512t_iv)
    return Sha512t.new.sha512t_truncate(sha512t_untruncated, t)
  end
end