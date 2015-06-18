# sha512t

A simple sha512 and sha512/t implementation from FIPS PUB 180-4.

## Installation

```bash
$ gem install sha512t
```

## Usage

To use sha512t-gem in ruby-file, simply require it.

```ruby
require 'sha512t'
```

To generate sha512 hash (returns hex-value as String)

```ruby
Sha512.hash('yourString')
```

To genereate sha512/t hash (returns hex-value as String).
For t, place an integer value which is a multiple of 8. The generated hash will be truncated to t bits.


```ruby
Sha512t.hash('yourString', t)
```