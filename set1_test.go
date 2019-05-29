// Tests for Cryptopals Challenges: Set 1
// author: Andreas Fleig

package main

import "testing"

// challange 2
import "bytes"
import "encoding/hex"

// challenge 6
import "strings"

// challenge 7
import "io/ioutil"
import "fmt"
import "encoding/base64"

// challenge 8
import "bufio"
import "os"

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
  hex, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
  if err != nil {
    t.Fatal(err)
  }
  res := singleByteXORCipher(hex)
  if bytes.Compare(res, []byte("Cooking MC's like a pound of bacon")) != 0 {
    t.Error("c3: wrong result", res, []byte("Cooking MC's like a pound of bacon"))
  }
}

func TestChallenge4(t *testing.T) {
  res := detectSingleCharacterXOR("./scXORs.txt")
  if res != 171 {
    t.Error("c4: wrong result", res)
  }
}

func TestChallenge5(t *testing.T) {
  res := repeatingKeyXOR("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE")

  if hex.EncodeToString(res) != "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" {
    t.Error("c5: wrong result", hex.EncodeToString(res))
  }
}

func TestCalcHammingDist(t *testing.T) {
  res := calcHammingDist([]byte("this is a test"), []byte("wokka wokka!!!"))

  if res != 37 {
    t.Error("c6/calcHammingDist: wrong result", res)
  }
}

func TestChallenge6(t *testing.T) {
  in, err := ioutil.ReadFile("./6.txt")
  if (err != nil) {
    fmt.Println(err)
  }
  data, err := base64.StdEncoding.DecodeString(string(in))
  if (err != nil) {
    fmt.Println(err)
  }
  res := findRepeatingKeyXORKey(data)
  if res != "Terminator X: Bring the noise" {
    t.Error("c6: wrong result", res)
  }
  plaintext := decipherRepeatingKeyXORWithKey("./6.txt", res)
  correctPlaintextPrefix := "I'm back and I'm ringin' the bell"
  if !strings.HasPrefix(plaintext, correctPlaintextPrefix){
    t.Error("c6: wrong result", plaintext[:len(correctPlaintextPrefix)])
  }
}

func TestChallenge7(t *testing.T) {
  key := []byte("YELLOW SUBMARINE")

  in, err := ioutil.ReadFile("./7.txt")
  if (err != nil) {
    fmt.Println(err)
  }

  ciphertext, err := base64.StdEncoding.DecodeString(string(in))
  if (err != nil) {
    fmt.Println(err)
  }

  plaintext := decryptAesEcb(key, ciphertext)
  correctPlaintextPrefix := "I'm back and I'm ringin' the bell"
  if !strings.HasPrefix(string(plaintext), correctPlaintextPrefix){
    t.Error("c6: wrong result", plaintext[:len(correctPlaintextPrefix)])
  }
}

func TestChallenge8(t *testing.T) {
  file, err := os.Open("./8.txt")
  if err != nil {
    fmt.Println(err)
  }
  defer file.Close()

  reader := bufio.NewReader(file)

  index := 0
  for {
    index++
    line, err := reader.ReadString('\n')
    if err != nil {
      // break at EOF
      break
    }
    hex, err := hex.DecodeString(line)
    if isAesEcb([]byte(hex), 16) {
      if index != 133 {
        t.Error("c8: wrong result: index ", index)
      }
    } else {
      if index == 133 {
        t.Error("c8: correct encryption not detected: index ", index)
      }
    }
  }
}
