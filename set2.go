// Cryptopals Challenges: Set 2
// author: Andreas Fleig

package main

import "fmt"

// challenge 9
import "bytes"

// challenge 10
import "crypto/aes"

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
