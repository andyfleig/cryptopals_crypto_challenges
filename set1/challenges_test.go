// Tests for Cryptopals Challenges: Set 1
// author: Andreas Fleig

package main

import "testing"

// challange 2
import "bytes"
import "encoding/hex"

func TestChallenge1(t *testing.T) {
  res := hextobase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
  if res != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
    t.Error("c1: wrong result", res)
  }
}

func TestChallenge2(t *testing.T) {
  v1, e1 := hex.DecodeString("1c0111001f010100061a024b53535009181c")
  v2, e2 := hex.DecodeString("686974207468652062756c6c277320657965")
  if e1 != nil {
    t.Fatal(e1)
  }
  if e2 != nil {
    t.Fatal(e2)
  }
  v, e := hex.DecodeString("746865206b696420646f6e277420706c6179")
  if e != nil {
    t.Fatal(e)
  }
  if !bytes.Equal(fixedXOR(v1, v2), v) {
    t.Error("c2: wrong result")
  }
}

func TestChallenge3(t *testing.T) {
  res := singleByteXORCipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
  if res != "Cooking MC's like a pound of bacon" {
    t.Error("c3: wrong result", res)
  }
}
