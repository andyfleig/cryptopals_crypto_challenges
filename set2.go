// Cryptopals Challenges: Set 2
// author: Andreas Fleig

package main

import (
	"encoding/base64"
	"fmt"
)

// challenge 9
import (
	"bytes"
)

// challenge 10
import (
	"crypto/aes"
)

// challenge 11
import (
	"math/rand"
	"time"
)

var (
	randomKey12 []byte
)

// challenge 9
func addPKCSPadding(in []byte, blockSize int) []byte {
	if len(in)%blockSize == 0 {
		return in
	}
	paddingLength := blockSize - (len(in) % blockSize)
	padding := bytes.Repeat([]byte("\x04"), paddingLength)
	return append(in, padding...)
}

func encryptAESECB(key []byte, plaintext []byte) []byte {
	keySize := len(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
	res := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext)-(keySize-1); i += keySize {
		block.Encrypt(res[i:i+keySize], plaintext[i:i+keySize])
	}
	return res
}

// challenge 10
func decryptAESCBC(key []byte, ciphertext []byte, iv []byte) []byte {
	blockSize := len(key)
	if len(ciphertext)%blockSize != 0 {
		panic("decryptAESECB: cipher length is not multiple of keySize")
	}

	result := []byte("")
	for i := 0; i < len(ciphertext); i += blockSize {
		currentBlock := ciphertext[i : i+blockSize]
		currentPlain := fixedXOR(decryptAESECB(key, currentBlock), iv)
		result = append(result, currentPlain...)
		iv = currentBlock
	}
	return result
}

func encryptAESCBC(key []byte, plaintext []byte, iv []byte) []byte {
	blockSize := len(key)
	plaintext = addPKCSPadding(plaintext, blockSize)

	result := []byte("")
	for i := 0; i < len(plaintext); i += blockSize {
		currentBlock := plaintext[i : i+blockSize]
		currentCipher := encryptAESECB(key, fixedXOR(currentBlock, iv))
		result = append(result, currentCipher...)
		iv = currentCipher
	}
	return result
}

// challenge 11
func createRandomAESKey() []byte {
	randomKey := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(randomKey)
	return randomKey
}

func encryptionOracle(plaintext []byte) (int, []byte) {
	rand.Seed(time.Now().UnixNano())
	// create random numbers between 5 and 10 (rand.Intn(6) creates random number in [0,6))
	prefixLength := rand.Intn(6) + 5
	suffixLength := rand.Intn(6) + 5
	randomPrefix := make([]byte, prefixLength)
	rand.Read(randomPrefix)
	randomSuffix := make([]byte, suffixLength)
	rand.Read(randomSuffix)
	input := append(append(randomPrefix, plaintext...), randomSuffix...)
	input = addPKCSPadding(input, 16)

	encMethod := rand.Intn(2)
	key := createRandomAESKey()
	if encMethod == 0 {
		return 0, encryptAESCBC(key, input, createRandomAESKey())
	} else {
		return 1, encryptAESECB(key, input)
	}
}

func decideEncryptionMethod(cipher []byte) int {
	if isAESECB(cipher, 16) {
		return 1
	} else {
		return 0
	}
}
