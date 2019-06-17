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

func TestChallenge11(t *testing.T) {
  number_of_tests := 1000
  plaintext := []byte("In the town where I was born Lived a man who sailed to sea And he told us of his life In the land of submarines So we sailed up to the sun 'Til we found a sea of green And we lived beneath the waves In our yellow submarine We all live in a yellow submarine Yellow submarine, yellow submarine We all live in a yellow submarine Yellow submarine, yellow submarine And our friends are all aboard Many more of them live next door And the band begins to play We all live in a yellow submarine Yellow submarine, yellow submarine We all live in a yellow submarine Yellow submarine, yellow submarine As we live a life of ease Everyone of us has all we need (has all we need) Sky of blue (sky of blue) and sea of green (and sea of green) In our yellow submarine (in our yellow, submarine, ha ha) We all live in a yellow submarine Yellow submarine, yellow submarine We all live in a yellow submarine Yellow submarine, yellow submarine We all live in a yellow submarine Yellow submarine, yellow submarine We all live in a yellow submarine Yellow submarine, yellow submarine")
  for i := 0; i < number_of_tests; i++ {
    mode, cipher := encryptionOracle(plaintext)
    detected_mode := decideEncryptionMethod(plaintext, cipher)
    if detected_mode != mode {
      msg := fmt.Sprintf("c11: detected %d but is %d", detected_mode, mode)
      t.Error(msg)
    }
  }



}
