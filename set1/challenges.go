// Cryptopals Challenges: Set 1
// author: Andreas Fleig

package main

import "fmt"

// challenge 1
import "encoding/base64"
import "encoding/hex"

// challange 2

func main() {

}

// challenge 1
func hextobase64(in string) string {
  res, err := hex.DecodeString(in)
  if err != nil {
    fmt.Println(err)
  }
  result := base64.StdEncoding.EncodeToString(res)
  return result
}

// challenge 2
func fixedXOR(in1 []byte, in2 []byte) []byte {
  if len(in1) != len(in2) {
    panic("Error: input-strings must have the same length")
  }
  result := make([]byte, len(in1))
  for i := 0; i < len(in1); i++ {
    result[i] = in1[i] ^ in2[i]
  }
  return result
}
