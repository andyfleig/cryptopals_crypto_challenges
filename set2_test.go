// Tests for Cryptopals Challenges: Set 2
// author: Andreas Fleig

package main

import (
	"fmt"
	"strings"
	"testing"
)

// challenge 10
import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
)

func TestChallenge9(t *testing.T) {
	res := addPKCSPadding([]byte("YELLOW SUBMARINE"), 20)
	if string(res) != "YELLOW SUBMARINE\x04\x04\x04\x04" {
		t.Error("c9: wrong result", res)
	}
}

func TestEncryptAesEcb(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	plaintext := []byte("I'm back and I'm ringin' the bel")
	res := encryptAESECB(key, plaintext)
	result := decryptAESECB(key, res)
	if string(result) != string(plaintext) {
		t.Error("c10: wrong result:", string(result))
	}
}

func TestChallenge10(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	iv := bytes.Repeat([]byte("\x00"), 16)

	in, err := ioutil.ReadFile("./10.txt")
	if err != nil {
		fmt.Println(err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(string(in))
	if err != nil {
		fmt.Println(err)
	}

	plaintext := decryptAESCBC(key, ciphertext, iv)
	result := encryptAESCBC(key, plaintext, iv)

	if string(result) != string(ciphertext) {
		t.Error("c10: wrong result")
	}
}

func TestChallenge11(t *testing.T) {
	numberOfTests := 1000
	plaintext := []byte("In the town where I was born Lived a man who sailed to sea And he told us of his life In the land of submarines So we sailed up to the sun 'Til we found a sea of green And we lived beneath the waves In our yellow submarine We all live in a yellow submarine Yellow submarine, yellow submarine We all live in a yellow submarine Yellow submarine, yellow submarine And our friends are all aboard Many more of them live next door And the band begins to play We all live in a yellow submarine Yellow submarine, yellow submarine We all live in a yellow submarine Yellow submarine, yellow submarine As we live a life of ease Everyone of us has all we need (has all we need) Sky of blue (sky of blue) and sea of green (and sea of green) In our yellow submarine (in our yellow, submarine, ha ha) We all live in a yellow submarine Yellow submarine, yellow submarine We all live in a yellow submarine Yellow submarine, yellow submarine We all live in a yellow submarine Yellow submarine, yellow submarine We all live in a yellow submarine Yellow submarine, yellow submarine")
	for i := 0; i < numberOfTests; i++ {
		mode, cipher := encryptionOracle(plaintext)
		detectedMode := decideEncryptionMethod(cipher)
		if detectedMode != mode {
			msg := fmt.Sprintf("c11: detected %d but is %d", detectedMode, mode)
			t.Error(msg)
		}
	}
}
func TestChallenge12(t *testing.T) {
	plaintext := attackRandomKeyECBWithTailingSecret()
	correctPlaintext := []byte{82, 111, 108, 108, 105, 110, 39, 32, 105, 110, 32, 109, 121, 32, 53, 46, 48, 10, 87, 105, 116, 104, 32, 109, 121, 32, 114, 97, 103, 45, 116, 111, 112, 32, 100, 111, 119, 110, 32, 115, 111, 32, 109, 121, 32, 104, 97, 105, 114, 32, 99, 97, 110, 32, 98, 108, 111, 119, 10, 84, 104, 101, 32, 103, 105, 114, 108, 105, 101, 115, 32, 111, 110, 32, 115, 116, 97, 110, 100, 98, 121, 32, 119, 97, 118, 105, 110, 103, 32, 106, 117, 115, 116, 32, 116, 111, 32, 115, 97, 121, 32, 104, 105, 10, 68, 105, 100, 32, 121, 111, 117, 32, 115, 116, 111, 112, 63, 32, 78, 111, 44, 32, 73, 32, 106, 117, 115, 116, 32, 100, 114, 111, 118, 101, 32, 98, 121, 10, 4, 4, 4, 4, 4, 4}
	if bytes.Compare(plaintext, correctPlaintext) != 0 {
		t.Error("c12: wrong result: ", string(plaintext[:len(correctPlaintext)]))
	}
}

func TestChallenge13(t *testing.T) {
	// test parseKeyValueString
	kvString := "foo=bar&baz=qux&zap=zazzle"
	res := parseKeyValueString(kvString)
	expected := "{foo: 'bar',baz: 'qux',zap: 'zazzle'}"
	if res != expected {
		t.Error("c13 parseKeyValueString: wrong result: ", res)
	}
	// test profileFor
	res = profileFor("foo@bar.com")
	expected = "email=foo@bar.com&uid=10&role=user"
	if res != expected {
		t.Error("c13 profileFor: wrong result: ", res)
	}

	res = profileFor("foo@bar.com&role=admin")
	expected = "email=foo@bar.comroleadmin&uid=10&role=user"
	if res != expected {
		t.Error("c13 profileFor: wrong result: ", res)
	}
	profile := createAdminProfile()
	res = decryptUserProfileUnderRandomKey(profile)
	if !strings.HasSuffix(res, "&role=admin") {
		t.Error("c13: attack not successful, result: ", res)
	}
}

func TestChallenge14(t *testing.T) {
	plaintext := attackRandomKeyECBWithPrefixAndSecret()
	correctPlaintext := []byte{82, 111, 108, 108, 105, 110, 39, 32, 105, 110, 32, 109, 121, 32, 53, 46, 48, 10, 87, 105, 116, 104, 32, 109, 121, 32, 114, 97, 103, 45, 116, 111, 112, 32, 100, 111, 119, 110, 32, 115, 111, 32, 109, 121, 32, 104, 97, 105, 114, 32, 99, 97, 110, 32, 98, 108, 111, 119, 10, 84, 104, 101, 32, 103, 105, 114, 108, 105, 101, 115, 32, 111, 110, 32, 115, 116, 97, 110, 100, 98, 121, 32, 119, 97, 118, 105, 110, 103, 32, 106, 117, 115, 116, 32, 116, 111, 32, 115, 97, 121, 32, 104, 105, 10, 68, 105, 100, 32, 121, 111, 117, 32, 115, 116, 111, 112, 63, 32, 78, 111, 44, 32, 73, 32, 106, 117, 115, 116, 32, 100, 114, 111, 118, 101, 32, 98, 121, 10, 4, 4, 4, 4, 4, 4}
	if bytes.Compare(plaintext, correctPlaintext) != 0 {
		t.Error("c12: wrong result: ", string(plaintext[:len(correctPlaintext)]))
	}
}
