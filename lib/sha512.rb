# FIPS PUB 180-4 SHA512 hashing
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

class Sha512
  def initialize
    # SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Constants
    @constants =  [  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
                    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
                    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
                    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 
                    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 
                    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
                    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
                    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 
                    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
                    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
                    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
                    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
                    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 ]
  end

  def preprocessing(message)
    # Preprocessing Step 1: Padding the message  
    bytes = message.bytes.to_a 
    l = bytes.size * 8
    padded_message = ""
    zero = "0"

    bytes.each do |byte|
      bit = byte.to_s(2)
      if bit.length < 8
        bit = (zero * (8 - bit.length)) + bit
      end
      padded_message += bit
    end
    
    # padding with a one bit
    padded_message += "1"
    
    # add k zero bits, where k is the smallest non-negative solution to the equation l+1+k = 896 mod 1024
    blocks = (896-(l+1))
    while blocks < 0 do
      blocks += 1024
    end
    padded_message += zero * blocks

    # append 128-bit block that is equal to the number of l expressed using a binary representation
    last_bit_block = l.to_s(2)
    if last_bit_block.length < 128
      last_bit_block = (zero * (128 - last_bit_block.length)) + last_bit_block
    end
    padded_message += last_bit_block

    # Preprocessing Step 2: Parsing the message
    parsed_message = []
    for block in 0..padded_message.size/64-1
      parsed_message.push(padded_message[(64*block)..(64*block)+63])
    end

    return parsed_message
  end

  def hash_computation(p, iv)
    # initial hash value
    h0 = iv[0]
    h1 = iv[1]
    h2 = iv[2]
    h3 = iv[3]
    h4 = iv[4]
    h5 = iv[5]
    h6 = iv[6]
    h7 = iv[7]

    for i in 1..p.size/15

      # Initialize the eight working variables, a, b, c, d, e, f, g, and h, with the (i-1)-st hash value:
      a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
      w = []

      for t in 0..79
        if t < 16
          w[t] = p[((i-1)*16) + t].to_i(2)
        else
          v1 = w[t-2]
          t1 = (v1>>19 | v1<<(64-19)) ^ (v1>>61 | v1<<(64-61)) ^ (v1 >> 6)
          v2 = w[t-15]
          t2 = (v2>>1 | v2<<(64-1)) ^ (v2>>8 | v2<<(64-8)) ^ (v2 >> 7)

          w[t] = (t1 + w[t-7] + t2 + w[t-16]) % (2**64)
        end

        t1 = h + ((e>>14 | e<<(64-14)) ^ (e>>18 | e<<(64-18)) ^ (e>>41 | e<<(64-41))) + ((e & f) ^ (~e & g)) + @constants[t] + w[t]
        t2 = ((a>>28 | a<<(64-28)) ^ (a>>34 | a<<(64-34)) ^ (a>>39 | a<<(64-39))) + ((a & b) ^ (a & c) ^ (b & c))

        h = g
        g = f
        f = e
        e = (d + t1) % (2**64)
        d = c
        c = b
        b = a
        a = (t1 + t2) % (2**64)
      end

      # Compute the i-th intermediate hash value H(i)
      h0 = (a + h0) % (2**64)
      h1 = (b + h1) % (2**64)
      h2 = (c + h2) % (2**64)
      h3 = (d + h3) % (2**64)
      h4 = (e + h4) % (2**64)
      h5 = (f + h5) % (2**64)      
      h6 = (g + h6) % (2**64)
      h7 = (h + h7) % (2**64)
    end

    hash = [ h0, h1, h2, h3, h4, h5, h6, h7 ]
    
    # Convert hash to hex-String    
    hash_string = ""
    hash.each do |h|
      temp = h.to_s(16)
      if temp.length < 16
        temp = "0" * (16 - temp.length) + temp
      end
      hash_string += temp
    end
    return hash_string
  end


  def self.hash(message)
    # SHA512 initial hash value from FIPS-180
    sha512_initial_hash_value = [ 0x6a09e667f3bcc908,
                                  0xbb67ae8584caa73b,
                                  0x3c6ef372fe94f82b,
                                  0xa54ff53a5f1d36f1,
                                  0x510e527fade682d1,
                                  0x9b05688c2b3e6c1f,
                                  0x1f83d9abfb41bd6b,
                                  0x5be0cd19137e2179 ]

    # Preprocessing
    #
    # consists of two steps: 
    # 1. padding the message,
    # 2. parsing the message into message blocks
    parsed_message = Sha512.new.preprocessing(message)

    # Hash Computation
    return Sha512.new.hash_computation(parsed_message, sha512_initial_hash_value)
  end
end