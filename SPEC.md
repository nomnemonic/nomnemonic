# nomnemonic spec

## Abstract

`nomnemonic` is a deterministic mnemonic generator that uses 3 inputs and cryptography to generate a mnemonic sentence.

Algorithm version: 3.0.0

## Motivation

There are several random mnemonic generation techniques. The most popular ones are true random and pseudo random mnemonic generators which are reliable sources for generating random mnemonics. But none of them provide any warranty to keep these 12-24 word lists in a safe place.

There are several products in the market which include NFC programmable taggers, stainless steel sheets, cards, hardware-wallet backups, and etc... At the end of the day, people become paranoid on how to safely secure the mnemonics. Some rent safe from the bank and store half. Some keep half in another family house, another city, country, and etc... When the time comes to access them for any reason, it takes significant effort.

This guide introduces a deterministic and cryptographic way to re-generate bip39 compatible with mnemonic words.

## User inputs

* `identifier` is an identifier like username/email/phone/etc... that can be at at least 2 chars is a must for decreasing the probability of predictability
* `password` is a password (strong password is suggested, at least 12 chars is must)
* `passcode` is a 6 digit number which can start with zeros
* `number_of_words` is an enum type which is valid list of bip39 compatible word sizes 12, 15, 18, 21 and 24

## Variables

`number_of_words = 24 # 12, 15, 18, 21, 24`

`seed = "<identifier>:<password>|<passcode>=<number_of_words>"`

`strength` is corresponding bit size for the `number_of_words`, the mapping is as below:

```
24 words --> 256 bits
21 words --> 224 bits
18 words --> 192 bits
15 words --> 160 bits
12 words --> 128 bits
```

## Entropy calculation

```
entropy_size = strength / 8

dk_head = pbkdf2.Key(seed, "pwd"+password+"code"+passcode, (1<<18), entropy_size, sha512.New)

dk_tail = scrypt.Key(seed, "pwd"+password+"code"+passcode, (1<<18), 8, 1, entropy_size)

0..entropy_size do
    entropy[i] = dk_head[i] ^ dk_tail[i]
end
```

## Generating the mnemonic

Mnemonic word generation uses the same process specified in [bip39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic) wiki.
