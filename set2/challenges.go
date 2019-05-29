// Cryptopals Challenges: Set 2
// author: Andreas Fleig

package main

// challenge 9
import "bytes"


func main() {

}

// challenge 9
func addPkcsPadding(in []byte, blocksize int) []byte {
  padding_length := blocksize - (len(in)%blocksize)
  padding := bytes.Repeat([]byte("\x04"), padding_length)
  return append(in, padding...)
}
