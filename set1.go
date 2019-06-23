// Cryptopals Challenges: Set 1
// author: Andreas Fleig

package main

import (
	"fmt"
)

// challenge 1
import (
	"encoding/base64"
	"encoding/hex"
)

// challenge 3
import (
	"bytes"
)

// challenge 4
import (
	"bufio"
	"os"
)

// challenge 6
import (
	"io/ioutil"
	"math"
	"math/bits"
)

// challenge 7
import (
	"crypto/aes"
)

func main() {

}

// challenge 1
func hexToBase64(in string) string {
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
func singleByteXORCipherWithScore(in []byte) ([]byte, byte, int) {
	// starting point r=32 because 32(dec) = 20(hex) = SP(ascii) which is the first "interesting" character
	r := 32

	bestScore := 0
	bestResult := make([]byte, len(in))
	bestKey := byte(r)
	// loop over all characters:
	// end point r=126 because 126(dec) = 7E(hex) = ~(ascii) which is the last "interesting" character
	for ; r < 127; r++ {
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
			char := result[i : i+1]
			if bytes.Equal(char, []byte(" ")) {
				score += 130
			}
			if bytes.Equal(char, []byte("e")) {
				score += 127
			}
			if bytes.Equal(char, []byte("E")) {
				score += 127
			}
			if bytes.Equal(char, []byte("t")) {
				score += 90
			}
			if bytes.Equal(char, []byte("T")) {
				score += 90
			}
			if bytes.Equal(char, []byte(".")) {
				score += 85
			}
			if bytes.Equal(char, []byte("a")) {
				score += 82
			}
			if bytes.Equal(char, []byte("A")) {
				score += 82
			}
			if bytes.Equal(char, []byte("o")) {
				score += 75
			}
			if bytes.Equal(char, []byte("O")) {
				score += 75
			}
			if bytes.Equal(char, []byte("i")) {
				score += 70
			}
			if bytes.Equal(char, []byte("I")) {
				score += 70
			}
			if bytes.Equal(char, []byte("n")) {
				score += 67
			}
			if bytes.Equal(char, []byte("N")) {
				score += 67
			}
			if bytes.Equal(char, []byte("s")) {
				score += 63
			}
			if bytes.Equal(char, []byte("S")) {
				score += 63
			}
			if bytes.Equal(char, []byte("h")) {
				score += 61
			}
			if bytes.Equal(char, []byte("H")) {
				score += 61
			}
			if bytes.Equal(char, []byte("r")) {
				score += 60
			}
			if bytes.Equal(char, []byte("R")) {
				score += 60
			}
			if bytes.Equal(char, []byte("d")) {
				score += 43
			}
			if bytes.Equal(char, []byte("D")) {
				score += 43
			}
			if bytes.Equal(char, []byte("l")) {
				score += 40
			}
			if bytes.Equal(char, []byte("c")) {
				score += 28
			}
			if bytes.Equal(char, []byte("u")) {
				score += 27
			}
			if bytes.Equal(char, []byte("m")) {
				score += 24
			}
			if bytes.Equal(char, []byte("w")) {
				score += 23
			}
		}

		if score > bestScore {
			bestResult = result
			bestScore = score
			bestKey = byte(r)
		}

	}
	return bestResult[:len(in)], bestKey, bestScore
}

func singleByteXORCipher(in []byte) []byte {
	res, _, _ := singleByteXORCipherWithScore(in)
	return res
}

// challenge 4
func detectSingleCharacterXOR(in string) int {
	inData, err := os.Open(in)
	if err != nil {
		fmt.Println(err)
	}

	scanner := bufio.NewScanner(inData)

	highestScore := 0
	counter := 1
	counterAtHighestScore := 0
	for scanner.Scan() {
		_, _, score := singleByteXORCipherWithScore([]byte(scanner.Text()))
		if score > highestScore {
			highestScore = score
			counterAtHighestScore = counter
		}
		counter++
	}
	return counterAtHighestScore
}

// challenge 5
func repeatingKeyXOR(msg string, key string) []byte {
	msgArr := []byte(msg)
	keyArr := []byte(key)

	result := make([]byte, len(msgArr))
	keyCharNumber := 0
	for i := 0; i < len(msgArr); i++ {
		msgElement := make([]byte, 1)
		msgElement[0] = msgArr[i]
		keyElement := make([]byte, 1)
		keyElement[0] = keyArr[keyCharNumber]
		result[i] = fixedXOR(msgElement, keyElement)[0]

		keyCharNumber++
		// loop over key-characters:
		if keyCharNumber >= len(keyArr) {
			keyCharNumber = 0
		}
	}
	return result
}

// challenge 6
func findRepeatingKeyXORSize(data []byte) int {
	//loop over key-lengths
	bestDist := math.MaxFloat64
	keyLength := 0
	for i := 2; i < 40; i++ {
		// find key length
		dist1 := calcHammingDist(data[:4*i], data[4*i:2*4*i])
		dist2 := calcHammingDist(data[2*4*i:3*4*i], data[3*4*i:4*4*i])

		resDist := ((float64(dist1 + dist2)) / float64(2)) / float64(i)

		if resDist < bestDist {
			bestDist = resDist
			keyLength = i
		}
	}
	return keyLength
}

func findRepeatingKeyXORKey(data []byte) string {
	keyLength := findRepeatingKeyXORSize(data)

	numberOfBlocks := (len(data) / keyLength) + 1
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
		_, k, _ := singleByteXORCipherWithScore(blocks[i])
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

func decipherRepeatingKeyXORWithKey(filePath string, key string) string {
	in, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println(err)
	}
	data, err := base64.StdEncoding.DecodeString(string(in))
	if err != nil {
		fmt.Println(err)
	}

	plaintext := string(repeatingKeyXOR(string(data), key))
	return plaintext
}

// challenge 7
func decryptAESECB(key []byte, cipher []byte) []byte {
	keySize := len(key)
	if len(cipher)%keySize != 0 {
		panic("decryptAESECB: cipher length is not multiple of keySize")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
	res := make([]byte, len(cipher))
	for i := 0; i < len(cipher); i += keySize {
		block.Decrypt(res[i:i+keySize], cipher[i:i+keySize])
	}
	return res
}

// challenge 8
func isAESECB(cipher []byte, blockSize int) bool {
	if len(cipher)%blockSize != 0 {
		return false
	}
	knownBlocks := make(map[string]struct{})
	// find cipher blocks with multiple occurrences
	for i := 0; i < len(cipher); i += blockSize {
		block := cipher[i : i+blockSize]
		_, ok := knownBlocks[string(block)]
		if ok {
			// multiple occurrence -> it is indeed AES ECB encrypted
			return true
		} else {
			// first occurrence -> add to map
			knownBlocks[string(block)] = struct{}{}
		}
	}
	return false
}
