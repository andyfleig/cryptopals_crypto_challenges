// Cryptopals Challenges: Set 1
// author: Andreas Fleig

package main

import "fmt"

// challenge 1
import "encoding/base64"
import "encoding/hex"


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
