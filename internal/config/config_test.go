// Package config controls server-side configuration
//
// The validation and definition of the configuration file is done within
// models and config is used to store logic related to server-side components
//
// Note: For unit tests packages that required access to the backend database
// were not replicated
//
// The package structure is broken into two components:
// config.go which contains the functions
// config_test.go which contains the unit tests
package config

import (
	"fmt"
	"ohaserver/internal/models"
	"reflect"
	"testing"
)

func TestDehexPlaintext(t *testing.T) {
	tests := []struct {
		input string
		plain string
		err   error
	}{
		{"$HEX[48656c6c6f20576f726c64]", "Hello World", nil},
		{"$HEX[48656c6c6f]", "Hello", nil},
		{"$HEX[48656c6c6f20576f726c64b", "Hello World", fmt.Errorf("error decoding hex string: 48656c6c6f20576f726c64b")},
		{"$HEX[]", "", nil},
	}

	for _, test := range tests {
		plain, err := DehexPlaintext(test.input)
		if plain != test.plain || (err != nil && test.err != nil && err.Error() != test.err.Error()) {
			t.Errorf("DehexPlaintext(%v) = (%v, %v), want (%v, %v)", test.input, plain, err, test.plain, test.err)
		}
	}
}

func TestRehashMD5(t *testing.T) {
	tests := []struct {
		input string
		hash  string
	}{
		{"password", "5f4dcc3b5aa765d61d8327deb882cf99"},
		{"12345", "827ccb0eea8a706c4c34a16891f84e7b"},
		{"test", "098f6bcd4621d373cade4e832627b4f6"},
	}

	for _, test := range tests {
		hash := RehashMD5(test.input)
		if hash != test.hash {
			t.Errorf("RehashMD5(%v) = %v, want %v", test.input, hash, test.hash)
		}
	}
}

func TestRehashSHA1(t *testing.T) {
	tests := []struct {
		input string
		hash  string
	}{
		{"password", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"},
		{"12345", "8cb2237d0679ca88db6464eac60da96345513964"},
		{"test", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"},
	}

	for _, test := range tests {
		hash := RehashSHA1(test.input)
		if hash != test.hash {
			t.Errorf("RehashSHA1(%v) = %v, want %v", test.input, hash, test.hash)
		}
	}
}

func TestRehashNTLM(t *testing.T) {
	tests := []struct {
		input string
		hash  string
	}{
		{"password", "8846f7eaee8fb117ad06bdd830b7586c"},
		{"12345", "7a21990fcd3d759941e45c490f143d5f"},
		{"test", "0cb6948805f797bf2a82807973b89537"},
	}

	for _, test := range tests {
		hash := RehashNTLM(test.input)
		if hash != test.hash {
			t.Errorf("RehashNTLM(%v) = %v, want %v", test.input, hash, test.hash)
		}
	}
}

func TestTestHexInput(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"$HEX[123abc]", true},
		{"$HEX[123ABC]", true},
		{"$HEX[123abC]", true},
		{"$HEX[123abC", false},
		{"HEX[123abC]", false},
		{"$HEX[]", true},
		{"$HEX", false},
	}

	for _, test := range tests {
		valid := TestHexInput(test.input)
		if valid != test.valid {
			t.Errorf("TestHexInput(%v) = %v, want %v", test.input, valid, test.valid)
		}
	}
}

func TestParseHashAndPlaintext(t *testing.T) {
	tests := []struct {
		input  interface{}
		cipher string
		plain  string
		err    error
	}{
		{"hash:plain", "hash", "plain", nil},
		{"hash:salt:plain", "hash:salt", "plain", nil},
		{"hash:salt:s:al:t:plain", "hash:salt:s:al:t", "plain", nil},
		{"invalid", "", "", fmt.Errorf("error parsing hash from plaintext: invalid")},
	}

	for _, test := range tests {
		cipher, plain, err := ParseHashAndPlaintext(test.input)
		if cipher != test.cipher || plain != test.plain || (err != nil && test.err != nil && err.Error() != test.err.Error()) {
			t.Errorf("ParseHashAndPlaintext(%v) = (%v, %v, %v), want (%v, %v, %v)", test.input, cipher, plain, err, test.cipher, test.plain, test.err)
		}
	}
}

func TestRehashUpload(t *testing.T) {
	md5Hashes := []string{
		"5f4dcc3b5aa765d61d8327deb882cf99:password",
		"i982d903e447368f3933999607f9b776a:hash:hash",
	}
	ntlmHashes := []string{
		"8846f7eaee8fb117ad06bdd830b7586c:password",
		"a6f03e97a08e1045c4ee5d5593241bef:hash:hash",
	}
	uploadStruct, err := RehashUpload(ntlmHashes, "0")
	if err != nil {
		t.Errorf("error rehashing hashes: %v", err)
	}
	if len(uploadStruct) != len(md5Hashes) {
		t.Errorf("expected %d hashes, got %d", len(md5Hashes), len(uploadStruct))
	}
	for i, h := range md5Hashes {
		_, p, _ := ParseHashAndPlaintext(h)
		expectedHash := fmt.Sprintf("%s:%s", RehashMD5(p), p)
		if uploadStruct[i] != expectedHash {
			t.Errorf("expected hash '%s', got '%s'", expectedHash, uploadStruct[i])
		}
	}
}

func TestValidateHashItem(t *testing.T) {
	hashStruct := models.HashStruct{
		Plaintext: "password",
		Algorithm: "0",
		Hash:      "5f4dcc3b5aa765d61d8327deb882cf99",
	}
	err := ValidateHashItem(hashStruct, "0")
	if err != nil {
		t.Errorf("error validating valid hash: %v", err)
	}

	hashStruct.Hash = "invalid_hash"
	err = ValidateHashItem(hashStruct, "0")
	if err == nil {
		t.Errorf("expected error validating invalid hash, got nil")
	}
	if err.Error() != "hashes do not match: 5f4dcc3b5aa765d61d8327deb882cf99 (rehashed) != invalid_hash (provided)" {
		t.Errorf("expected error message 'hashes do not match: 5f4dcc3b5aa765d61d8327deb882cf99 (rehashed) != invalid_hash (provided)', got '%s'", err.Error())
	}

	hashStruct.Algorithm = "100"
	hashStruct.Hash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
	err = ValidateHashItem(hashStruct, "100")
	if err != nil {
		t.Errorf("error validating valid SHA1 hash: %v", err)
	}

	hashStruct.Algorithm = "1000"
	hashStruct.Hash = "8846f7eaee8fb117ad06bdd830b7586c"
	err = ValidateHashItem(hashStruct, "1000")
	if err != nil {
		t.Errorf("error validating valid NTLM hash: %v", err)
	}
}

func TestStringToToggle(t *testing.T) {
	tests := []struct {
		str   string
		index int
		want  string
	}{
		{"HelloWorld", 0, "T0 T5"},
		{"HelloWorld", 5, "T5 TA"},
	}

	for _, test := range tests {
		got := StringToToggle(test.str, test.index)
		if got != test.want {
			t.Errorf("StringToToggle(%q, %q) = %q; want %q", test.str, test.index, got, test.want)
		}
	}
}

func TestCharToRule(t *testing.T) {
	tests := []struct {
		str  string
		rule string
		want string
	}{
		{"hello", "^", "^h ^e ^l ^l ^o"},
		{"world", "$", "$w $o $r $l $d"},
	}

	for _, test := range tests {
		got := CharToRule(test.str, test.rule)
		if got != test.want {
			t.Errorf("CharToRule(%q, %q) = %q; want %q", test.str, test.rule, got, test.want)
		}
	}
}

func TestCheckASCIIString(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"Hello, 世界", false},
		{"Hello, World!", true},
		{"", true},
		{"世界", false},
	}

	for _, test := range tests {
		result := CheckASCIIString(test.input)
		if result != test.expected {
			t.Errorf("CheckASCIIString(%q) = %v; want %v", test.input, result, test.expected)
		}
	}
}

func TestConvertCharacterMultiByteString(t *testing.T) {
	tests := []struct {
		name string
		str  string
		want string
	}{
		{
			name: "All ASCII characters",
			str:  "$H $e $l $l $o $ $W $o $r $l $d $!",
			want: "$H $e $l $l $o $ $W $o $r $l $d $!",
		},
		{
			name: "Contains non-ASCII character",
			str:  "$H $e $l $l $o $  $世 $界 $!",
			want: "$H $e $l $l $o $  $\\xE4 $\\xB8 $\\x96 $\\xE7 $\\x95 $\\x8C $!",
		},
		{
			name: "Contains non-ASCII character with ^",
			str:  "^! ^界 ^世 ^  ^o ^l ^l ^e ^H",
			want: "^! ^\\x8C ^\\x95 ^\\xE7 ^\\x96 ^\\xB8 ^\\xE4 ^  ^o ^l ^l ^e ^H",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertCharacterMultiByteString(tt.str)
			if got != tt.want {
				t.Errorf("ConvertCharacterMultiByteString(%q) = %v, want %v", tt.str, got, tt.want)
			}
		})
	}
}

func TestMakeMask(t *testing.T) {
	str := "Hello, World1!"
	replacements := ConstructReplacements("ulds")
	want := "?u?l?l?l?l?s?s?u?l?l?l?l?d?s"
	got := MakeMask(str, replacements)
	if got != want {
		t.Errorf("MakeMask(%q, %q) = %q; want %q", str, replacements, got, want)
	}
}

func TestConvertMaskMultiByteString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "Hello, 世界",
			want:  "Hello, ?b?b?b?b?b?b",
		},
		{
			input: "",
			want:  "",
		},
		{
			input: "Hello",
			want:  "Hello",
		},
		{
			input: "?u?l?l?l?l世界",
			want:  "?u?l?l?l?l?b?b?b?b?b?b",
		},
	}

	for _, test := range tests {
		got := ConvertMaskMultiByteString(test.input)
		if got != test.want {
			t.Errorf("ConvertMaskMultiByteString(%q) = %v; want %v",
				test.input, got, test.want)
		}
	}
}

func TestConstructReplacements(t *testing.T) {
	tests := []struct {
		name string
		str  string
		want []string
	}{
		{
			name: "Test lower case",
			str:  "l",
			want: []string{"a", "?l", "b", "?l", "c", "?l", "d", "?l", "e", "?l", "f", "?l", "g", "?l", "h", "?l", "i", "?l", "j", "?l", "k", "?l", "l", "?l", "m", "?l", "n", "?l", "o", "?l", "p", "?l", "q", "?l", "r", "?l", "s", "?l", "t", "?l", "u", "?l", "v", "?l", "w", "?l", "x", "?l", "y", "?l", "z", "?l"},
		},
		{
			name: "Test upper case",
			str:  "u",
			want: []string{"A", "?u", "B", "?u", "C", "?u", "D", "?u", "E", "?u", "F", "?u", "G", "?u", "H", "?u", "I", "?u", "J", "?u", "K", "?u", "L", "?u", "M", "?u", "N", "?u", "O", "?u", "P", "?u", "Q", "?u", "R", "?u", "S", "?u", "T", "?u", "U", "?u", "V", "?u", "W", "?u", "X", "?u", "Y", "?u", "Z", "?u"},
		},
		{
			name: "Test digits",
			str:  "d",
			want: []string{"0", "?d", "1", "?d", "2", "?d", "3", "?d", "4", "?d", "5", "?d", "6", "?d", "7", "?d", "8", "?d", "9", "?d"},
		},
		{
			name: "Test special characters",
			str:  "s",
			want: []string{" ", "?s", "!", "?s", "\"", "?s", "#", "?s", "$", "?s", "%", "?s", "&", "?s", "\\", "?s", "(", "?s", ")", "?s", "*", "?s", "+", "?s", ",", "?s", "-", "?s", ".", "?s", "/", "?s", ":", "?s", ";", "?s", "<", "?s", "=", "?s", ">", "?s", "?", "?s", "@", "?s", "[", "?s", "\\", "?s", "]", "?s", "^", "?s", "_", "?s", "`", "?s", "{", "?s", "|", "?s", "}", "?s", "~", "?s", "'", "?s"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConstructReplacements(tt.str)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ConstructReplacements() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReverseString(t *testing.T) {
	tests := []struct {
		str  string
		want string
	}{
		{"hello", "olleh"},
		{"world", "dlrow"},
	}

	for _, test := range tests {
		got := ReverseString(test.str)
		if got != test.want {
			t.Errorf("ReverseString(%q) = %q; want %q", test.str, got, test.want)
		}
	}
}

func TestContainsSubstring(t *testing.T) {
	tests := []struct {
		word       string
		substrings []string
		expected   bool
	}{
		{"password123", []string{"pass", "123"}, true},
		{"applepie", []string{"banana", "orange"}, false},
		{"helloworld", []string{}, false},
		{"", []string{"a", "b"}, false},
	}

	for _, test := range tests {
		result := containsSubstring(test.word, test.substrings)
		if result != test.expected {
			t.Errorf("Word '%s' with substrings %v: expected %v, got %v", test.word, test.substrings, test.expected, result)
		}
	}
}

func TestHasUniqueChars(t *testing.T) {
	tests := []struct {
		str      string
		expected bool
	}{
		{"ABCDefg123", true},
		{"apie", true},
		{"", false},
		{"aA", false},
	}

	for _, test := range tests {
		result := hasUniqueChars(test.str)
		if result != test.expected {
			t.Errorf("String '%s': expected %v, got %v", test.str, test.expected, result)
		}
	}
}
