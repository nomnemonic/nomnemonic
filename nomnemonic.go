package nomnemonic

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const (
	_bitChunkSizeOneByte        = 8  // 1 byte = 8 bits
	_bitChunkSizeBip39WordIndex = 11 // bip39 word index is 11 bits
	_bitChunkSizeEntropy        = 32 // mnemonic must encode entropy in a multiple of 32 bits

	_saltPrefixMnemonic = "mnemonic"
	_saltPrefixPassword = "pwd"
	_saltPrefixPasscode = "code"

	_inputIdentifierMinLength = 2
	_inputPasscodeLength      = 6
	_inputPasswordMinLength   = 12

	Version          = "0.3.0"
	VersionAlgorithm = "3.0.0"
)

var (
	_strengths = map[int]struct{}{
		256: {},
		224: {},
		192: {},
		160: {},
		128: {},
	}

	_sentenceStrengths = map[int]int{
		24: 256,
		21: 224,
		18: 192,
		15: 160,
		12: 128,
	}
)

type (
	mnemonicer struct {
		words []string
		dict  map[string]int
	}

	Mnemonicer interface {
		Generate(identifier, password, passcode string, size int) ([]string, error)
		CalculateEntropy(words []string) ([]byte, error)
		GenerateSeed(sentence, passphrase string) ([]byte, error)
		GenerateSeed32(sentence, passphrase string) ([]byte, error)
		IsValid(words []string) (bool, error)
	}
)

// New inits a new mnemonic generator
func New(words []string) (Mnemonicer, error) {
	if len(words) != 2048 {
		return nil, errors.New("bip39 is based on 2048 words")
	}
	dict := make(map[string]int, len(words))
	for i, w := range words {
		dict[w] = i
	}
	return &mnemonicer{
		words: words,
		dict:  dict,
	}, nil
}

// Generate generates mnemonic words for identifier, password, passcode and size
func (m *mnemonicer) Generate(identifier, password, passcode string, size int) ([]string, error) {
	if len(identifier) < _inputIdentifierMinLength {
		return nil, fmt.Errorf("identifier must be at least %d chars", _inputIdentifierMinLength)
	}

	if len(password) < _inputPasswordMinLength {
		return nil, fmt.Errorf("password must be at least %d chars", _inputPasswordMinLength)
	}

	if len(passcode) != _inputPasscodeLength {
		return nil, fmt.Errorf("passcode must be %d digits", _inputPasscodeLength)
	}

	_, err := strconv.Atoi(passcode)
	if err != nil {
		return nil, fmt.Errorf("passcode must be numeric but given '%s'", passcode)
	}

	strength := _sentenceStrengths[size]
	err = m.validateStrength(strength)
	if err != nil {
		return nil, err
	}

	input := []byte(fmt.Sprintf("%s:%s|%s=%d", identifier, password, passcode, size))
	entropySize := strength / _bitChunkSizeOneByte
	dkHead := pbkdf2.Key(
		input,
		[]byte(_saltPrefixPassword+password+_saltPrefixPasscode+passcode),
		(1 << 18),
		entropySize,
		sha512.New,
	)
	dkTail, _ := scrypt.Key(
		input,
		[]byte(_saltPrefixPassword+password+_saltPrefixPasscode+passcode),
		(1 << 18),
		8,
		1,
		entropySize,
	)

	entropy := make([]byte, entropySize)
	for i := 0; i < entropySize; i++ {
		entropy[i] = dkHead[i] ^ dkTail[i]
	}
	bins := bytesToBin(entropy)

	// get word indexes
	csSize := strength / _bitChunkSizeEntropy
	mnemonicSize := (strength + csSize) / _bitChunkSizeBip39WordIndex
	prefixSize := _bitChunkSizeBip39WordIndex - csSize
	wordIndexes := chunkSplit(bins[:strength-prefixSize], _bitChunkSizeBip39WordIndex)
	words := make([]string, mnemonicSize)
	for i, wi := range wordIndexes {
		words[i] = m.words[binToInt(wi)]
	}

	// generate last word from checksum of n-1 words and n-checksum size random
	// prefix
	cs := m.checksum(entropy, csSize)
	prefix := bins[strength-prefixSize:]
	words[mnemonicSize-1] = m.words[binToInt(prefix+cs)]

	return words, nil
}

// CalculateEntropy calculates entropy from words
func (m *mnemonicer) CalculateEntropy(words []string) ([]byte, error) {
	strength := _sentenceStrengths[len(words)]
	bins, err := m.buildBins(strength, words)
	if err != nil {
		return nil, err
	}

	entropy := binToBytes(bins[:strength])
	csSize := strength / _bitChunkSizeEntropy
	cs := m.checksum(entropy, csSize)
	if cs == bins[strength:] {
		return entropy, nil
	}

	return nil, errors.New("invalid checksum")
}

// GenerateSeed generates 64 bytes seed using the mnemonic sentence and
// passphrase
func (m *mnemonicer) GenerateSeed(sentence, passphrase string) ([]byte, error) {
	seed := pbkdf2.Key([]byte(sentence), []byte(_saltPrefixMnemonic+passphrase), 2048, 64, sha512.New)
	return seed, nil
}

// GenerateSeed32 generates 32 bytes seed using the mnemonic sentence and
// passphrase
func (m *mnemonicer) GenerateSeed32(sentence, passphrase string) ([]byte, error) {
	seed := pbkdf2.Key([]byte(sentence), []byte(_saltPrefixMnemonic+passphrase), 4096, 32, sha512.New)
	return seed, nil
}

// IsValid checks if the given mnemonic words are valid from the bip39 word list
// and validates checksum from the n-1 words
func (m *mnemonicer) IsValid(words []string) (bool, error) {
	strength := _sentenceStrengths[len(words)]
	bins, err := m.buildBins(strength, words)
	if err != nil {
		return false, err
	}

	entropy := binToBytes(bins[:strength])
	csSize := strength / _bitChunkSizeEntropy
	cs := m.checksum(entropy, csSize)

	if cs == bins[strength:] {
		return true, nil
	}

	return false, nil
}

func (m *mnemonicer) buildBins(strength int, words []string) (string, error) {
	err := m.validateStrength(strength)
	if err != nil {
		return "", err
	}

	err = m.validateWordsPrecense(words)
	if err != nil {
		return "", err
	}

	bins := ""
	for _, w := range words {
		bins += intToBin(m.dict[w], _bitChunkSizeBip39WordIndex)
	}
	return bins, nil
}

func (m *mnemonicer) checksum(entropy []byte, size int) string {
	sum := sha256.Sum256(entropy)
	return fmt.Sprintf("%08b", sum[0])[:size]
}

func (m *mnemonicer) validateStrength(s int) error {
	_, exists := _strengths[s]
	if !exists {
		return fmt.Errorf("unsupported strength: %d", s)
	}
	return nil
}

func (m *mnemonicer) validateWordsPrecense(words []string) error {
	for _, w := range words {
		_, ok := m.dict[w]
		if !ok {
			return fmt.Errorf("unrecognized word %s", w)
		}
	}
	return nil
}

func binToBytes(bitString string) []byte {
	lenB := len(bitString)/_bitChunkSizeOneByte + 1
	bs := make([]byte, lenB)

	count, i := 0, 0
	var current byte
	for _, v := range bitString {
		if count == _bitChunkSizeOneByte {
			bs[i] = current
			i++
			current, count = 0, 0
		}
		current = current<<1 + byte(v-'0')
		count++
	}
	if count != 0 {
		bs[i] = current << (_bitChunkSizeOneByte - byte(count))
		i++
	}

	bs = bs[:i:i]
	return bs
}

func bytesToBin(vals []byte) string {
	val := ""
	for _, n := range vals {
		val += fmt.Sprintf("%08b", n)
	}
	return val
}

func intToBin(n, bits int) string {
	format := fmt.Sprintf("%%0%db", bits)
	return fmt.Sprintf(format, n)
}

func binToInt(n string) int {
	i, _ := strconv.ParseInt(n, 2, 64)
	return int(i)
}

func chunkSplit(s string, size int) []string {
	chunks := make([]string, 0, len(s)/size)
	l := len(s) / size
	for i := 0; i < l; i++ {
		chunks = append(chunks, s[i*size:(i+1)*size])
	}
	return chunks
}
