// Cryptopals Challenges: Set 2
// author: Andreas Fleig

package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"strings"
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
	"time"
)

var aesBlockSize = 16

// challenge 12
var (
	randomKey12 []byte
)

// challenge 13
var (
	randomKey13 []byte
)

// challenge 14
var (
	randLength int
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
	randomKey := make([]byte, aesBlockSize)
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
	input = addPKCSPadding(input, aesBlockSize)

	encMethod := rand.Intn(2)
	key := createRandomAESKey()
	if encMethod == 0 {
		return 0, encryptAESCBC(key, input, createRandomAESKey())
	} else {
		return 1, encryptAESECB(key, input)
	}
}

func decideEncryptionMethod(cipher []byte) int {
	if isAESECB(cipher, aesBlockSize) {
		return 1
	} else {
		return 0
	}
}

// challenge 12
func encryptECBUnderRandomKeyWithTailingSecret(buffer []byte) []byte {
	s := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	secret, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		fmt.Println("Error decoding string.")
	}
	// input is (given buffer || secret string)
	input := addPKCSPadding(append(buffer, secret...), aesBlockSize)
	if len(randomKey12) == 0 {
		randomKey12 = createRandomAESKey()
	}
	return encryptAESECB(randomKey12, input)
}

func attackRandomKeyECBWithTailingSecret() []byte {
	// 1&2: detect blockSize and that it actually is ECB
	// has to start with blockSize = 2
	// has to be double the size since two following blocks have to be identical to detect via isAESECB
	buffer := []byte("AAAA")
	encBuf := encryptECBUnderRandomKeyWithTailingSecret(buffer)
	var blockSize int
	for blockSize = 2; blockSize < 100; blockSize++ {
		if isAESECB(encBuf, blockSize) {
			break
		}
		buffer = append(buffer, "AA"...)
		encBuf = encryptECBUnderRandomKeyWithTailingSecret(buffer)
	}

	deciphered := ""
	for i := 0; i < len(encryptECBUnderRandomKeyWithTailingSecret([]byte{})); i++ {
		blockNumber := int(i / blockSize)
		blockOffset := blockNumber * blockSize
		// 3. crafting input block which is one byte short
		dummy := bytes.Repeat([]byte("A"), blockSize-(i%blockSize)-1)
		inBlock := append(dummy, []byte(deciphered)...)

		// 4. create dictionary
		dict := make(map[string]string)
		for j := 0; j < 256; j++ {
			cur := append(inBlock, []byte(string(j))...)
			cur = encryptECBUnderRandomKeyWithTailingSecret(cur)[blockOffset : blockOffset+blockSize]
			dict[string(cur)] = string(j)
		}
		character, ok := dict[string(encryptECBUnderRandomKeyWithTailingSecret(dummy)[blockOffset:blockOffset+blockSize])]
		if ok {
			deciphered += character
		} else {
			log.Fatal("Error: no entry found in dict!")
		}
	}
	return []byte(deciphered)
}

// challenge 13
func parseKeyValueString(kvString string) string {
	parts := strings.Split(kvString, "&")
	result := "{"
	for _, part := range parts {
		kv := strings.Split(part, "=")
		if len(kv) != 2 {
			log.Fatal("Invalid kv-string!")
		}
		result += kv[0] + ": " + "'" + kv[1] + "',"
	}
	// cut off tailing comma and add final "}"
	result = result[:len(result)-1] + "}"
	return result
}

func profileFor(email string) string {
	// remove meta chars ("&" and "="):
	email = strings.ReplaceAll(email, "&", "")
	email = strings.ReplaceAll(email, "=", "")

	var parts []string
	parts = append(parts, "email="+email)
	parts = append(parts, "uid="+"10")
	parts = append(parts, "role="+"user")
	result := ""
	for _, part := range parts {
		result += part + "&"
	}
	return result[:len(result)-1]
}

func encryptUserProfile(userProfile string, key []byte) []byte {
	return encryptAESECB(key, addPKCSPadding([]byte(userProfile), aesBlockSize))
}
func encryptUserProfileUnderRandomKey(userProfile string) []byte {
	if len(randomKey13) == 0 {
		randomKey13 = createRandomAESKey()
	}
	return encryptUserProfile(userProfile, randomKey13)
}

func decryptUserProfile(cipher []byte, key []byte) string {
	return string(decryptAESECB(key, cipher))
}

func decryptUserProfileUnderRandomKey(cipher []byte) string {
	if len(randomKey13) == 0 {
		randomKey13 = createRandomAESKey()
	}
	return string(removePKCSPadding([]byte(decryptUserProfile(cipher, randomKey13))))
}

func removePKCSPadding(in []byte) []byte {
	ctr := 0
	for in[len(in)-1] == []byte("\x04")[0] {
		in = in[:len(in)-1]
		ctr++
		if ctr == aesBlockSize {
			log.Fatal("Padding must not be longer than one block!")
		}
	}
	return in
}

func createAdminProfile() []byte {
	// fixed layout since the content of the profile is fixed except for the mail which is attacker controlled
	// idea:
	// 1) create a block (somewhere within the encrypted profile) containing the word "admin" and the rest of the block is the padding element "\x04"
	// 2) create a profile where the "user" part is in the beginning of the last block (so the second last block ends with "role="
	// 3) add the block from 1 to the end to create a part "role=admin" for the user
	// email=dummydummyadmin00000000000123&uid=10&role=user
	// |-blocksize=16-||-blocksize=16-||-blocksize=16-|
	dummyProfile := []byte("dummydummyadmin")
	dummyProfile = append(dummyProfile, bytes.Repeat([]byte("\x04"), 11)...)
	dummyProfile = append(dummyProfile, []byte("123")...)
	dummyCipher := encryptUserProfileUnderRandomKey(profileFor(string(dummyProfile)))
	adminBlock := dummyCipher[aesBlockSize : 2*aesBlockSize]

	// 19 is the length of the profile with an empty mail and without a user role ("email=&uid=10&role=")
	email := bytes.Repeat([]byte("a"), 2*aesBlockSize-19)
	cipher := encryptUserProfileUnderRandomKey(profileFor(string(email)))
	cipher = append(cipher[:len(cipher)-aesBlockSize], adminBlock...)
	return cipher
}

// challenge 14
func encryptECBUnderRandomKeyWithPrefixAndSecret(buffer []byte) []byte {
	if randLength == 0 {
		rand.Seed(time.Now().UnixNano())
		// define random length between 5 and 30
		randLength = rand.Intn(25) + 5
	}
	randomPrefix := make([]byte, randLength)
	rand.Read(randomPrefix)
	input := append(randomPrefix, buffer...)
	// input is (random prefix || given buffer || secret string)
	return encryptECBUnderRandomKeyWithTailingSecret(input)
}

func hasDuplicateECBBlocks(cipher []byte) int {
	for i := 0; i < len(cipher)-aesBlockSize; i++ {
		block := cipher[i : i+aesBlockSize]
		if bytes.Contains(cipher[i+aesBlockSize:], block) {
			return i
		}
	}
	return -1
}

func encOracle(buffer []byte, padding []byte, prefPadLength int) []byte {
	buf := append(padding, buffer...)
	res := encryptECBUnderRandomKeyWithPrefixAndSecret(buf)
	return res[prefPadLength:]
}

func attackRandomKeyECBWithPrefixAndSecret() []byte {
	// find length of prefix:
	var prefixLength int
	var foundLength bool
	for i := 0; i < aesBlockSize; i++ {
		buffer := bytes.Repeat([]byte("A"), i)
		buffer = append(buffer, bytes.Repeat([]byte("B"), aesBlockSize*2)...)
		cipher := encryptECBUnderRandomKeyWithPrefixAndSecret(buffer)
		shift := hasDuplicateECBBlocks(cipher)
		if shift != -1 {
			// calculate the number of blocks to shift depending on the position of the found duplicate
			blockShift := int(shift / aesBlockSize)
			prefixLength = blockShift*aesBlockSize - i
			foundLength = true
			break
		}
	}
	if !foundLength {
		log.Fatal("Error: could not find length of random prefix.")
	}
	// padding is necessary to fill up the current block to ensure the buffer starts with a new block
	paddingLength := aesBlockSize - (prefixLength % aesBlockSize)
	padding := bytes.Repeat([]byte("A"), paddingLength)
	prefPadLength := paddingLength + prefixLength

	// rest of the attack like before:
	deciphered := ""
	for i := 0; i < len(encOracle([]byte{}, padding, prefPadLength)); i++ {
		blockNumber := int(i / aesBlockSize)
		blockOffset := blockNumber * aesBlockSize
		// 3. crafting input block which is one byte short
		dummy := bytes.Repeat([]byte("A"), aesBlockSize-(i%aesBlockSize)-1)
		inBlock := append(dummy, []byte(deciphered)...)

		// 4. create dictionary
		dict := make(map[string]string)
		for j := 0; j < 256; j++ {
			cur := append(inBlock, []byte(string(j))...)
			cur = encOracle(cur, padding, prefPadLength)[blockOffset : blockOffset+aesBlockSize]
			dict[string(cur)] = string(j)
		}
		character, ok := dict[string(encOracle(dummy, padding, prefPadLength)[blockOffset:blockOffset+aesBlockSize])]
		if ok {
			deciphered += character
		} else {
			log.Fatal("Error: no entry found in dict!")
		}
	}
	return []byte(deciphered)

}
