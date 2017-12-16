// Tests for Cryptopals Challenges: Set 1
// author: Andreas Fleig

package main

import "testing"

func TestChallenge1(t *testing.T) {
  res := hextobase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
  if res != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
    t.Error("wrong result", res)
  }
}
