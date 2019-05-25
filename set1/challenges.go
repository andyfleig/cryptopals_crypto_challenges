// Cryptopals Challenges: Set 1
// author: Andreas Fleig

package main

import "fmt"

// challenge 1
import "encoding/base64"
import "encoding/hex"

// challenge 3
import "bytes"

// challenge 4
import "os"
import "bufio"

// challenge 6
import "math"
import "math/bits"
import "io/ioutil"

// challenge 7
import "crypto/aes"

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

// challenge 3
func singleByteXORCipherWithScore(in []byte) ([]byte,byte,int) {
  // starting point r=32 because 32(dec) = 20(hex) = SP(ascii) which is the first "interesting" character
  r := 32

  best_score := 0
  best_result := make([]byte, len(in))
  best_key := byte(r)
  // loop over all characters:
  // end point r=126 because 126(dec) = 7E(hex) = ~(ascii) which is the last "interesting" character
  for ;r < 127; r++ {
    // create byte slice with same length as in and all characters are r:
    arr := make([]byte, len(in))
    for i := 0; i < len(in); i++ {
      arr[i] = byte(r)
    }
    // XOR the two byte slices
    result := fixedXOR(arr, in)

    // score the result:
    score := 0
    for i := 0; i < len(result); i++ {
      char := result[i:i+1]
      if (bytes.Equal(char, []byte(" "))) {score += 130}
      if (bytes.Equal(char, []byte("e"))) {score += 127}
      if (bytes.Equal(char, []byte("E"))) {score += 127}
      if (bytes.Equal(char, []byte("t"))) {score += 90}
      if (bytes.Equal(char, []byte("T"))) {score += 90}
      if (bytes.Equal(char, []byte("."))) {score += 85}
      if (bytes.Equal(char, []byte("a"))) {score += 82}
      if (bytes.Equal(char, []byte("A"))) {score += 82}
      if (bytes.Equal(char, []byte("o"))) {score += 75}
      if (bytes.Equal(char, []byte("O"))) {score += 75}
      if (bytes.Equal(char, []byte("i"))) {score += 70}
      if (bytes.Equal(char, []byte("I"))) {score += 70}
      if (bytes.Equal(char, []byte("n"))) {score += 67}
      if (bytes.Equal(char, []byte("N"))) {score += 67}
      if (bytes.Equal(char, []byte("s"))) {score += 63}
      if (bytes.Equal(char, []byte("S"))) {score += 63}
      if (bytes.Equal(char, []byte("h"))) {score += 61}
      if (bytes.Equal(char, []byte("H"))) {score += 61}
      if (bytes.Equal(char, []byte("r"))) {score += 60}
      if (bytes.Equal(char, []byte("R"))) {score += 60}
      if (bytes.Equal(char, []byte("d"))) {score += 43}
      if (bytes.Equal(char, []byte("D"))) {score += 43}
      if (bytes.Equal(char, []byte("l"))) {score += 40}
      if (bytes.Equal(char, []byte("c"))) {score += 28}
      if (bytes.Equal(char, []byte("u"))) {score += 27}
      if (bytes.Equal(char, []byte("m"))) {score += 24}
      if (bytes.Equal(char, []byte("w"))) {score += 23}
    }

    if (score > best_score) {
      best_result = result
      best_score = score
      best_key = byte(r)
    }

  }
  return best_result[:len(in)],best_key,best_score
}

func singleByteXORCipher(in []byte) []byte {
  res,_,_ := singleByteXORCipherWithScore(in)
  return res
}

// challenge 4
func detectSingleCharacterXOR(in string) int {
  inData, err := os.Open(in)
  if (err != nil) {
    fmt.Println(err)
  }

  scanner := bufio.NewScanner(inData)

  highest_score := 0
  counter := 1
  counter_at_highest_score := 0
  for scanner.Scan() {
    _,_,score := singleByteXORCipherWithScore([]byte(scanner.Text()))
    if (score > highest_score) {
      highest_score = score
      counter_at_highest_score = counter
    }
    counter++
  }
  return counter_at_highest_score
}

// challenge 5
func repeatingKeyXOR(msg string, key string) []byte{
  msg_arr := []byte(msg)
  key_arr := []byte(key)

  result := make([]byte, len(msg_arr))
  key_char_number := 0
  for i := 0; i < len(msg_arr); i++ {
    msg_element := make([]byte, 1)
    msg_element[0] = msg_arr[i]
    key_element := make([]byte, 1)
    key_element[0] = key_arr[key_char_number]
    result[i] = fixedXOR(msg_element, key_element)[0]

    key_char_number++
    // loop over key-characters:
    if (key_char_number >= len(key_arr)) {
      key_char_number = 0
    }
  }
  return result
}

// challenge 6
func findRepeatingKeyXORKey(filePath string) string{
  in, err := ioutil.ReadFile(filePath)
  if (err != nil) {
    fmt.Println(err)
  }
  data, err := base64.StdEncoding.DecodeString(string(in))
  if (err != nil) {
    fmt.Println(err)
  }

  //loop over key-lenghts
  bestDist := math.MaxFloat64
  keyLength := 0
  for i := 2; i < 40; i++ {
    // find key length
    dist1 := calcHammingDist(data[:4*i], data[4*i:2*4*i])
    dist2 := calcHammingDist(data[2*4*i:3*4*i], data[3*4*i:4*4*i])

    resDist := ((float64(dist1 + dist2))/float64(2))/float64(i)

    if resDist < bestDist {
      bestDist = resDist
      keyLength = i
    }
  }

  numberOfBlocks := (len(data)/keyLength)+1
  blocks := make([][]byte, keyLength)
  for i := range blocks {
    blocks[i] = make([]byte, numberOfBlocks)
  }

  dataElement := 0
  for j := 0; j < numberOfBlocks; j++ {
    for i := 0; i < keyLength; i++ {

      if dataElement < len(data) {
        blocks[i][j] = data[dataElement]
        dataElement++
      }
    }
  }

  key := make([]byte, keyLength)
  for i := 0; i < keyLength; i++ {
    _,k,_ := singleByteXORCipherWithScore(blocks[i])
    key[i] = k
  }
  return string(key)
}

func calcHammingDist(in1, in2 []byte) int {
  if len(in1) != len(in2) {
    panic("calcHammingDist: inputs must have same length")
  }
  hammingDistance := 0

  for i := 0; i < len(in1); i++ {
    hammingDistance += bits.OnesCount8(in1[i] ^ in2[i])
  }
  return hammingDistance
}

func decipherRepeatingKeyXORWithKey(filePath string, key string) string{
  in, err := ioutil.ReadFile(filePath)
  if (err != nil) {
    fmt.Println(err)
  }
  data, err := base64.StdEncoding.DecodeString(string(in))
  if (err != nil) {
    fmt.Println(err)
  }

  plaintext := string(repeatingKeyXOR(string(data), key))
  return plaintext
}

// challenge 7
func decryptAesEcb(key, cipher []byte) []byte{
  keysize := len(key)
  block, err := aes.NewCipher(key)
  if (err != nil) {
    fmt.Println(err)
  }
  res := make([]byte, len(cipher))
  for i := 0; i < len(cipher) - keysize; i += keysize {
    block.Decrypt(res[i:i+keysize], cipher[i:i+keysize])
  }
  return res
}




//
