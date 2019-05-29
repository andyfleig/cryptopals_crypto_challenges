// Tests for Cryptopals Challenges: Set 2
// author: Andreas Fleig

package main

import "testing"
import "fmt"

// challenge 10
import "bytes"
import "io/ioutil"
import "encoding/base64"

func TestChallenge9(t *testing.T) {
  res := addPkcsPadding([]byte("YELLOW SUBMARINE"), 20)
  if string(res) != "YELLOW SUBMARINE\x04\x04\x04\x04" {
    t.Error("c9: wrong result", res)
  }
}

func TestEncryptAesEcb(t *testing.T) {
  key := []byte("YELLOW SUBMARINE")
  plaintext := []byte("I'm back and I'm ringin' the bel")
  res := encryptAesEcb(key, plaintext)
  result := decryptAesEcb(key, res)
  if string(result) != string(plaintext) {
    t.Error("c10: wrong result:", string(result))
  }
}

func TestChallenge10(t *testing.T) {
  key := []byte("YELLOW SUBMARINE")
  iv := bytes.Repeat([]byte("\x00"), 16)

  in, err := ioutil.ReadFile("./10.txt")
  if (err != nil) {
    fmt.Println(err)
  }

  ciphertext, err := base64.StdEncoding.DecodeString(string(in))
  if (err != nil) {
    fmt.Println(err)
  }

  plaintext := decryptAesCbc(key, ciphertext, iv)
  result := encryptAesCbc(key, plaintext, iv)


  if string(result) != string(ciphertext) {
    t.Error("c10: wrong result")
  }
}
