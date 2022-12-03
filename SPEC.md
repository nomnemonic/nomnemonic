# nomnemonic spec

## Abstract

`nomnemonic` is a deterministic mnemonic generator that uses 3 inputs and cryptography to generate a mnemonic sentence.

Algorithm version: 2.0.0

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

`seed = "<identifier>:<password>|<passcode>"`

`dk = pbkdf2.Key(seed, "password"+password), 4096, 32, sha512.New)`

`encrypted = aes.NewCipher(dk).Encrypt(seed)`

`number_of_words = 24 # 12, 15, 18, 21, 24`

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
iterations = number_of_words + (passcode % 32)

entropy32 = sha.Sum256(encrypted)
for 0..iterations-1 do
    entropy32 = sha.Sum256(entropy32)
end

# either before or after convertion to binary limit the size with strength
# both would generate the same result
entropy256 = to_binary(entropy32)
entropy = entropy256[:strength]
```

## Generating the mnemonic

Mnemonic word generation uses the same process specified in [bip39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic) wiki.
