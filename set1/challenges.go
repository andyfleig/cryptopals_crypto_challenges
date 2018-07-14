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
import "strings"
import "io/ioutil"

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
func singleByteXORCipherWithScore(in string) (string,int) {
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
  return string(best_result[:len(in_arr)]),best_score
}


// challenge 4
func singleByteXORCipher(in string) string {
  res, _ := singleByteXORCipherWithScore(in)
  return res
}

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
    _,score := singleByteXORCipherWithScore(scanner.Text())
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
func breakRepeatingKeyXOR(filePath string) {
  in, err := ioutil.ReadFile(filePath)
  if (err != nil) {
    fmt.Println(err)
  }
  data, err := base64.StdEncoding.DecodeString(string(in))
  if (err != nil) {
    fmt.Println(err)
  }
  cypher := string(data)

  //loop over key-lenghts
  bestDist := math.MaxFloat64
  keyLength := 0
  for i := 2; i < 40; i++ {
    // find key length
    dist1 := calcHammingDist(cypher[:4*i], cypher[4*i:2*4*i])
    dist2 := calcHammingDist(cypher[2*4*i:3*4*i], cypher[3*4*i:4*4*i])

    resDist := ((float64(dist1 + dist2))/float64(5))/float64(i)

    if resDist < bestDist {
      bestDist = resDist
      keyLength = i
    }
  }
  fmt.Println("probable length:", keyLength)
  // bestElem = key-length

  // brake in blocks of length-elements: list[0::length]

}

func calcHammingDist(in1 string, in2 string) int {
  bin1 := stringToBin(in1)
  bin2 := stringToBin(in2)
  minLen := math.Min(float64(len(bin1)), float64(len(bin2)))
  hammingDistance := 0

  for i := 0; i < int(minLen); i++ {
    if (bin1[i] != bin2[i]) {
      hammingDistance++
    }
  }
  // calculate number of ones in the rest (longer-shorter) of the longer string
  ones := 0
  if (len(bin1) > len(bin2)) {
    tmp := bin1[int(minLen):len(bin1)]
    ones = strings.Count(string(tmp), "1");
  } else {
    tmp := bin2[int(minLen):len(bin2)]
    ones = strings.Count(string(tmp), "1");
  }
  hammingDistance += ones
  return hammingDistance
}

func stringToBin(in string) (out string) {
  for _, c := range in {
    out = fmt.Sprintf("%s%.8b", out, c)
  }
  return
}









//
