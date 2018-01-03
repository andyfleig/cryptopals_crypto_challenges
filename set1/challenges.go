// Cryptopals Challenges: Set 1
// author: Andreas Fleig

package main

import "fmt"

// challenge 1
import "encoding/base64"
import "encoding/hex"

// challange 3
import "bytes"

func main() {
  singleByteXORCipher("ETAOIN SHRDLU")
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

func singleByteXORCipher(in string) string {
  in_hex, err := hex.DecodeString(in)
  if err != nil {
    fmt.Println(err)
  }

  in_arr := []byte(in_hex)
  r := 'a'
  r = 33

  best_score := 0
  best_result := make([]byte, len(in_hex))
  // loop over all characters:
  for ;r < 127; r++ {
    // create byte slice with same length as in and all characters are r:
    arr := make([]byte, len(in_arr))
    for i := 0; i < len(in_arr); i++ {
      arr[i] = byte(r)
    }
    // XOR the two byte slices
    result := fixedXOR(arr, in_arr)

    // score the result:
    score := 0
    for i := 0; i < len(result); i++ {
      char := result[i:i+1]
      if (bytes.Equal(char, []byte("e"))) {score += 127}
      if (bytes.Equal(char, []byte("t"))) {score += 90}
      if (bytes.Equal(char, []byte("a"))) {score += 82}
      if (bytes.Equal(char, []byte("o"))) {score += 75}
      if (bytes.Equal(char, []byte("i"))) {score += 70}
      if (bytes.Equal(char, []byte("n"))) {score += 67}
      if (bytes.Equal(char, []byte("s"))) {score += 63}
      if (bytes.Equal(char, []byte("h"))) {score += 61}
      if (bytes.Equal(char, []byte("r"))) {score += 60}
      if (bytes.Equal(char, []byte("d"))) {score += 43}

      if (bytes.Equal(char, []byte("*"))) {score -= 100}
    }

    if (score > best_score) {
      best_result = result
      best_score = score
    }

  }
  return string(best_result[:len(in_arr)])
  // loop over all characters:

}
