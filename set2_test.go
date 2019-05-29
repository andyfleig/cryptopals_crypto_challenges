// Tests for Cryptopals Challenges: Set 2
// author: Andreas Fleig

package main

import "testing"


func TestChallenge9(t *testing.T) {
  res := addPkcsPadding([]byte("YELLOW SUBMARINE"), 20)
  if string(res) != "YELLOW SUBMARINE\x04\x04\x04\x04" {
    t.Error("c9: wrong result", res)
  }
}
