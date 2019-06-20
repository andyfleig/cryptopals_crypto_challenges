// Cryptopals Challenges: Set 2
// author: Andreas Fleig

package main

import (
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

// challenge 9
func addPkcsPadding(in []byte, blockSize int) []byte {
	if len(in)%blockSize == 0 {
		return in
	}
	paddingLength := blockSize - (len(in) % blockSize)
	padding := bytes.Repeat([]byte("\x04"), paddingLength)
	return append(in, padding...)
}

func encryptAesEcb(key []byte, plaintext []byte) []byte {
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
func decryptAesCbc(key []byte, ciphertext []byte, iv []byte) []byte {
	blockSize := len(key)
	if len(ciphertext)%blockSize != 0 {
		panic("decryptAesEcb: cipher length is not multiple of keySize")
	}

	result := []byte("")
	for i := 0; i < len(ciphertext); i += blockSize {
		currentBlock := ciphertext[i : i+blockSize]
		currentPlain := fixedXOR(decryptAesEcb(key, currentBlock), iv)
		result = append(result, currentPlain...)
		iv = currentBlock
	}
	return result
}

func encryptAesCbc(key []byte, plaintext []byte, iv []byte) []byte {
	blockSize := len(key)
	plaintext = addPkcsPadding(plaintext, blockSize)

	result := []byte("")
	for i := 0; i < len(plaintext); i += blockSize {
		currentBlock := plaintext[i : i+blockSize]
		currentCipher := encryptAesEcb(key, fixedXOR(currentBlock, iv))
		result = append(result, currentCipher...)
		iv = currentCipher
	}
	return result
}

// challenge 11
func createRandomAesKey() []byte {
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
	input = addPkcsPadding(input, 16)

	// randomly choose encryption method (ECB/CBC)
	encMethod := rand.Intn(2)
	key := createRandomAesKey()
	if encMethod == 0 {
		return 0, encryptAesCbc(key, input, createRandomAesKey())
	} else {
		return 1, encryptAesEcb(key, input)
	}
}

func decideEncryptionMethod(cipher []byte) int {
	if isAesEcb(cipher, 16) {
		return 1
	} else {
		return 0
	}
}
