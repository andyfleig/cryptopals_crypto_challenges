// Cryptopals Challenges: Set 2
// author: Andreas Fleig

package main

import "fmt"

// challenge 9
import "bytes"

// challenge 10
import "crypto/aes"

// challenge 11
import "math/rand"
import "time"


// challenge 9
func addPkcsPadding(in []byte, blocksize int) []byte {
  if len(in)%blocksize == 0 {
    return in
  }
  padding_length := blocksize - (len(in)%blocksize)
  padding := bytes.Repeat([]byte("\x04"), padding_length)
  return append(in, padding...)
}

func encryptAesEcb(key []byte, plaintext []byte) []byte{
  keysize := len(key)
  block, err := aes.NewCipher(key)
  if (err != nil) {
    fmt.Println(err)
  }
  res := make([]byte, len(plaintext))
  for i := 0; i < len(plaintext) - (keysize-1); i += keysize {
    block.Encrypt(res[i:i+keysize], plaintext[i:i+keysize])
  }
  return res
}

// challenge 10
func decryptAesCbc(key []byte, ciphertext []byte, iv []byte) []byte{
  blocksize := len(key)
  if len(ciphertext)%blocksize != 0 {
		panic("decryptAesEcb: cipher length is not multiple of keysize")
	}

  result := []byte("")
  for i := 0; i < len(ciphertext); i += blocksize{
    current_block := ciphertext[i:i+blocksize]
    current_plain := fixedXOR(decryptAesEcb(key, current_block), iv)
    result = append(result, current_plain...)
    iv = current_block
  }
  return result
}

func encryptAesCbc(key []byte, plaintext []byte, iv []byte) []byte{
  blocksize := len(key)
  plaintext = addPkcsPadding(plaintext, blocksize)

  result := []byte("")
  for i := 0; i < len(plaintext); i += blocksize{
    current_block := plaintext[i:i+blocksize]
    current_cipher := encryptAesEcb(key, fixedXOR(current_block, iv))
    result = append(result, current_cipher...)
    iv = current_cipher
  }
  return result
}

// challenge 11
func createRandomAesKey() []byte {
  random_key := make([]byte, 16)
  rand.Seed(time.Now().UnixNano())
  rand.Read(random_key)
  return random_key
}

func encryptionOracle(plaintext []byte) (int, []byte) {
  rand.Seed(time.Now().UnixNano())
  // create random numbers between 5 and 10 (rand.Intn(6) creates random number in [0,6))
  prefix_length := rand.Intn(6) + 5
  suffix_length := rand.Intn(6) + 5
  random_prefix := make([]byte, prefix_length)
  rand.Read(random_prefix)
  radnom_suffix := make([]byte, suffix_length)
  rand.Read(radnom_suffix)
  input := append(append(random_prefix, plaintext...), radnom_suffix...)
  input = addPkcsPadding(input, 16)

  // randomly choose encryption method (ECB/CBC)
  enc_method := rand.Intn(2)
  key := createRandomAesKey()
  if enc_method != 0 && enc_method != 1 {
    fmt.Println("ERROR")
  }
  if enc_method == 0 {
    return 0, encryptAesCbc(key, input, createRandomAesKey())
  } else {
    return 1, encryptAesEcb(key, input)
  }
}

func decideEncryptionMethod(plaintext []byte, cipher []byte) int {
  if isAesEcb(cipher, 16) {
    return 1
  } else {
    return 0
  }
}
