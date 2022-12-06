package nomnemonic

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	t.Run("invalid input word list", func(t *testing.T) {
		m, err := New([]string{})
		if err.Error() != "bip39 is based on 2048 words" {
			t.Errorf("error messages do not match")
		}
		if m != nil {
			t.Errorf("expected nil but not nil")
		}
	})

	t.Run("valid input word list", func(t *testing.T) {
		words, err := buildWords()
		if err != nil {
			t.Error("couldn't load words")
		}
		m, err := New(words)
		if err != nil {
			t.Errorf("expected nil err but actual %s", err.Error())
		}
		if m == nil {
			t.Errorf("couldn't initialize mnemonicer")
		}
	})
}

func TestGenerate(t *testing.T) {
	words, err := buildWords()
	if err != nil {
		t.Error("couldn't load words")
	}

	m, err := New(words)
	if err != nil {
		t.Errorf("unexpected error")
	}

	tests := []struct {
		identifier string
		password   string
		passcode   string
		size       int
		err        error
		sentence   string
	}{
		{
			size:       24,
			identifier: "nomnemonic_test",
			password:   "test12345678",
			passcode:   "101938",
			sentence:   "dress mule bonus strong village clip volcano public plug fossil travel lobster nerve love gospel dance shove vicious valve else roof observe warrior magic",
		},
		{
			size:       21,
			identifier: "nomnemonic_test",
			password:   "test12345678",
			passcode:   "101938",
			sentence:   "helmet trap peasant popular man busy arch crater spike warm banner before abuse dice govern jealous bread poet shy delay opinion",
		},
		{
			size:       18,
			identifier: "nomnemonic_test",
			password:   "test12345678",
			passcode:   "101938",
			sentence:   "loud youth skin earth sunny stone lift february oblige fee minute solve junior solid citizen blossom virtual noise",
		},
		{
			size:       15,
			identifier: "nomnemonic_test",
			password:   "test12345678",
			passcode:   "101938",
			sentence:   "scan labor slice similar party face cliff private siren narrow uncover reason staff pulp anchor",
		},
		{
			size:       12,
			identifier: "nomnemonic_test",
			password:   "test12345678",
			passcode:   "101938",
			sentence:   "cinnamon venue broken old brass vague paddle unaware critic alarm consider hobby",
		},
		{
			size:       12,
			identifier: "te",             // min size identifier
			password:   "paSZW0rD!.1234", // >=12 size password
			passcode:   "101938",         // 6 digit passcode
			sentence:   "clap acid hawk fox sock someone segment pole tissue own depth pioneer",
		},
		// validations
		{
			size:       11,
			identifier: "nomnemonic_test",
			password:   "test12345678",
			passcode:   "101938",
			err:        errors.New("unsupported strength: 0"),
		},
		{
			size:       12,
			identifier: "",
			password:   "test12345678",
			passcode:   "101938",
			err:        errors.New("identifier must be at least 2 chars"),
		},
		{
			size:       12,
			identifier: "te",
			password:   "",
			passcode:   "101938",
			err:        errors.New("password must be at least 12 chars"),
		},
		{
			size:       12,
			identifier: "te",
			password:   "test12345678",
			passcode:   "",
			err:        errors.New("passcode must be 6 digits"),
		},
		{
			size:       12,
			identifier: "te",
			password:   "test12345678",
			passcode:   "12345a",
			err:        errors.New("passcode must be numeric but given '12345a'"),
		},
		{
			size:       12,
			identifier: "te",
			password:   "test12345678",
			passcode:   "a12345",
			err:        errors.New("passcode must be numeric but given 'a12345'"),
		},
	}

	for _, test := range tests {
		sentence, err := m.Generate(test.identifier, test.password, test.passcode, test.size)
		if err != nil && test.err == nil {
			t.Errorf("unexpected error for size %d: %s", test.size, err.Error())
		}

		if test.err == nil {
			// compare expected sizes
			if len(sentence) != test.size {
				t.Errorf("couldn't generate correct size of mnemonics, want: %d, actual: %d", test.size, len(sentence))
			}

			// compare words
			actual := strings.Join(sentence, " ")
			if actual != test.sentence {
				t.Errorf("couldn't generate deterministic mnemonics, want: %s, actual: %s", test.sentence, actual)
			}
		}

		// on expected error fail
		if test.err != nil && err == nil {
			t.Errorf("expected err(%s) for size %d but actual nil", test.err.Error(), test.size)
		}

		// on expected errors, compare the error string
		if test.err != nil && err != nil && test.err.Error() != err.Error() {
			t.Errorf("expected err for size %d is '%s' but actual '%s'", test.size, test.err.Error(), err.Error())
		}
	}
}

func TestCalculateEntropy(t *testing.T) {
	words, err := buildWords()
	if err != nil {
		t.Error("couldn't load words")
	}

	m, err := New(words)
	if err != nil {
		t.Errorf("unexpected error")
	}

	tests := []struct {
		sentence string
		entropy  []byte
		err      error
	}{
		{
			sentence: "edge defense waste choose enrich upon flee junk siren film clown finish luggage leader kid quick brick print evidence swap drill paddle truly occur",
			entropy:  []byte{70, 71, 47, 222, 148, 36, 177, 221, 214, 51, 202, 201, 106, 200, 176, 43, 136, 76, 253, 30, 149, 125, 27, 181, 89, 55, 109, 164, 47, 61, 186, 92},
		},
		{
			sentence: "edge defense waste choose enrich upon flee junk siren film clown finish luggage leader kid quick brick print evidence swap drill paddle truly sure",
			err:      errors.New("invalid checksum"),
		},
		{
			sentence: "edge defense waste choose enrich upon flee junk siren film clown",
			err:      errors.New("unsupported strength: 0"),
		},
		{
			sentence: "tester defense waste choose enrich upon flee junk siren film clown finish luggage leader kid quick brick print evidence swap drill paddle truly occur",
			err:      errors.New("unrecognized word tester"),
		},
	}

	for _, test := range tests {
		entropy, err := m.CalculateEntropy(strings.Split(test.sentence, " "))
		if test.err != nil && err == nil {
			t.Errorf("expected err for the sentence (%s) but actual nil", test.sentence)
		}
		if test.err != nil && test.err.Error() != err.Error() {
			t.Errorf("expected err '%s' for the sentence (%s) but actual '%s'", test.err.Error(), test.sentence, err.Error())
		}
		if test.err == nil && !bytes.Equal(test.entropy, entropy) {
			t.Errorf("expected entropy for sentence (%s) %v but actual %v", test.sentence, test.entropy, entropy)
		}
	}
}

func TestGenerateSeed(t *testing.T) {
	words, err := buildWords()
	if err != nil {
		t.Error("couldn't load words")
	}

	m, err := New(words)
	if err != nil {
		t.Errorf("unexpected error")
	}

	sentence := "edge defense waste choose enrich upon flee junk siren film clown finish luggage leader kid quick brick print evidence swap drill paddle truly occur"

	tests := []struct {
		passphrase string
		expected   string
	}{
		{
			passphrase: "",
			expected:   "7e74b1a8195ae1e8d06f29c9a306f678e5a8cf908075bc52eb3b716f9e50ce8860065c2c18b8a960bb363855d3a340074cba5db505d4f78dd1d94c4e19f20b7a",
		},
		{
			passphrase: "some password",
			expected:   "0dc285fde768f7ff29b66ce7252d56ed92fe003b605907f7a4f683c3dc8586d34a914d3c71fc099bb38ee4a59e5b081a3497b7a323e90cc68f67b5837690310c",
		},
	}

	for _, test := range tests {
		seed, err := m.GenerateSeed(sentence, test.passphrase)
		if err != nil {
			t.Errorf("couldn't generate seed from sentence: %s", err)
		}

		actual := fmt.Sprintf("%x", seed)

		if actual != test.expected {
			t.Errorf("expected: '%s' but actual: '%s'", test.expected, actual)
		}
	}
}

func TestGenerateSeed32(t *testing.T) {
	words, err := buildWords()
	if err != nil {
		t.Error("couldn't load words")
	}

	m, err := New(words)
	if err != nil {
		t.Errorf("unexpected error")
	}

	sentence := "edge defense waste choose enrich upon flee junk siren film clown finish luggage leader kid quick brick print evidence swap drill paddle truly occur"

	tests := []struct {
		passphrase string
		expected   string
	}{
		{
			passphrase: "",
			expected:   "80eb719264248cf6d2fad85e42a00fcb09e0b85d2457d9f8185245da1c8bf9cf",
		},
		{
			passphrase: "some password",
			expected:   "5aa339790b2964bf24f7da082fe4dde2e7cae30caf4cf454b2d5a3871633f564",
		},
	}

	for _, test := range tests {
		seed, err := m.GenerateSeed32(sentence, test.passphrase)
		if err != nil {
			t.Errorf("couldn't generate seed from sentence: %s", err)
		}

		actual := fmt.Sprintf("%x", seed)

		if actual != test.expected {
			t.Errorf("expected: '%s' but actual: '%s'", test.expected, actual)
		}
	}
}

func TestIsValid(t *testing.T) {
	words, err := buildWords()
	if err != nil {
		t.Error("couldn't load words")
	}

	m, err := New(words)
	if err != nil {
		t.Errorf("unexpected error")
	}

	tests := []struct {
		sentence string
		valid    bool
	}{
		{
			sentence: "hope industry forget tell track random noise episode inner clog tackle trip fire ring shadow edit crouch maze arrange include crime fault yellow stumble",
			valid:    true,
		},
		{
			// wrong checksum
			sentence: "hope industry forget tell track random noise episode inner clog tackle trip fire ring shadow edit crouch maze arrange include crime fault yellow random",
			valid:    false,
		},
		{
			// invalid word count
			sentence: "hope industry forget tell track random noise episode inner clog tackle trip fire ring shadow edit crouch maze arrange include crime fault yellow",
			valid:    false,
		},
	}

	for _, test := range tests {
		actual, _ := m.IsValid(strings.Split(test.sentence, " "))
		if test.valid != actual {
			t.Errorf("expected %t but actual %t", test.valid, actual)
		}
	}
}

func buildWords() ([]string, error) {
	bytes, err := os.ReadFile("./test/english.txt")
	if err != nil {
		return nil, err
	}
	words := strings.Split(string(bytes), "\n")
	return words, nil
}
