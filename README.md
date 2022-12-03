# no mnemonic

[![Build Status](https://travis-ci.com/nomnemonic/nomnemonic.svg?branch=main)](https://travis-ci.com/github/nomnemonic/nomnemonic)
[![Coverage Status](https://coveralls.io/repos/github/nomnemonic/nomnemonic/badge.svg?branch=main)](https://coveralls.io/github/nomnemonic/nomnemonic?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/nomnemonic/nomnemonic)](https://goreportcard.com/report/github.com/nomnemonic/nomnemonic)
[![GoDoc](https://godoc.org/github.com/nomnemonic/nomnemonic?status.svg)](https://godoc.org/github.com/nomnemonic/nomnemonic)

`nomnemonic` is a deterministic mnemonic generator library that uses 3 inputs and cryptographic hash functions to generate the words.

The library is an implementation of the spec which aims to provide an alternative way for like-minded people/machines to have mnemonic words but also want to access to the seed in the future without any seed storage needs.

**Inputs**

* Identifier with any size (at least 2 chars)
* Password with any size (at least 8 chars)
* 6 digit numeric pass code
* Number of words: 12, 15, 18, 21, 24

**Cryptography**

* `pbkdf2` with `sha512`
* `aes256`
* `sha256.Sum256` (other algorithms can be addable)

**Outputs**

* Mnemonic words

## Algorithm

Please refer to [SPEC.md](./SPEC.md)

## License

Apache License 2.0

Copyright (c) 2022 nomnemonic

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
