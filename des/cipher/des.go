package cipher

import (
	"bytes"
	"errors"
	"fmt"
	"os"
)

//8 bytes, 64 bits for per DES block.
const BLOCK_SIZE = 8

type DesCipher struct {
	key    [8]byte
	subKey [16][6]byte
	cbcMode bool
}

func NewDesCipher(key []byte, cbcMode bool) (*DesCipher, error) {
	//Key len is 64 bits
	if len(key) != 8 {
		return nil, errors.New("encryption key length should be exactly 8")
	}

	var cipherKey [8]byte
	copy(cipherKey[:], key)
	cipher := &DesCipher{
		key: cipherKey,
		cbcMode: cbcMode,
	}
	cipher.generateSubKey()
	return cipher, nil
}

//Encrypt the input data, returns the encrypted data.
func (cipher *DesCipher) EncryptData(originData []byte) ([]byte, error) {
	return cipher.processData(originData, true)
}

//Decrypt the input data, returns the decrypted data.
func (cipher *DesCipher) DecryptData(originData []byte) ([]byte, error) {
	return cipher.processData(originData, false)
}

//Since the decryption and encryption of DES are very similar processes,
//process them in one function body.
func (cipher *DesCipher) processData(originData []byte, encrypt bool) ([]byte, error) {
	blocksCount := len(originData) / 8
	//Key as initial vector
	cbcVector := cipher.key[:]
	if len(originData)%8 != 0 {
		if !encrypt {
			return nil, errors.New("input data for decryption is invalid")
		}
		blocksCount++
	}

	outputData := make([]byte, 0, len(originData)+BLOCK_SIZE-(len(originData)%BLOCK_SIZE))
	for i := 0; i < blocksCount; i++ {
		var block []byte
		tempVector := make([]byte, 8)
		if len(originData) < (i+1)*BLOCK_SIZE {
			if len(originData) > i * BLOCK_SIZE {
				block = originData[i*BLOCK_SIZE:]
			} else {
				block = make([]byte, 0, 8)
			}
			pkcs7Padding(&block)
		} else {
			block = originData[i*BLOCK_SIZE : (i+1)*BLOCK_SIZE]
			if encrypt && i == blocksCount - 1 {
				blocksCount++
			}
		}
		if cipher.cbcMode {
			if encrypt{
				for index := range block {
					block[index] ^= cbcVector[index]
				}
			} else {
				copy(tempVector, block)
			}
		}
		permuted := initialPermute(block)
		left := permuted[:4]
		right := permuted[4:]
		if encrypt {
			for k := 0; k < 16; k++ {
				newLeft := make([]byte, 4)
				copy(newLeft, right)
				feistelResult := feistel(right, cipher.subKey[k])
				for index := range left {
					right[index] = left[index] ^ feistelResult[index]
				}
				copy(left, newLeft)
			}
		} else {
			for k := 0; k < 16; k++ {
				newLeft := make([]byte, 4)
				copy(newLeft, right)
				feistelResult := feistel(right, cipher.subKey[15-k])
				for index := range left {
					right[index] = left[index] ^ feistelResult[index]
				}
				copy(left, newLeft)
			}
		}
		var temp [4]byte
		copy(temp[:], left)
		copy(left, right)
		copy(right, temp[:])
		finalData := permute(permuted, fPermuteTable[:])
		if cipher.cbcMode {
			if encrypt {
				cbcVector = finalData
			} else {
				for index := range finalData {
					finalData[index] ^= cbcVector[index]
				}
				cbcVector = tempVector
			}
		}
		if !encrypt && i == blocksCount-1 {
			err := pkcs7Unpadding(&finalData)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Unpadding Error: %v", err)
			}
		}
		outputData = append(outputData, finalData...)
	}
	return outputData, nil
}

//Generates 16 48-bit subkeys from the object's 64-bit key
func (cipher *DesCipher) generateSubKey() {
	permutedKey := permute(cipher.key[:], pc1Table[:])
	cdKey := make([]byte, 8)
	copy(cdKey[:4], permutedKey[:4])
	copy(cdKey[4:], permutedKey[3:])
	for i := 0; i < 16; i++ {
		//left and right is each 32 bits, but only 28 bits will be used
		left, right := cdKey[:4], cdKey[4:]
		var offset uint
		switch i + 1 {
		case 1, 2, 9, 16:
			offset = 1
		default:
			offset = 2
		}
		copy(cdKey[:4], leftRotate(left, offset, 0, 4))
		copy(cdKey[4:], leftRotate(right, offset, 4, 8))
		var subKey [8]byte
		copy(subKey[:3], cdKey[:3])
		subKey[3] = (cdKey[3] & 0xf0) | (cdKey[4] & 0x0f)
		copy(subKey[4:], cdKey[5:])
		copy(cipher.subKey[i][:], permute(subKey[:], pc2Table[:]))
	}
}

//left rotate the byte slice, offset should only be 1 or 2.
//Assume last byte length is at least 2
func leftRotate(origin []byte, offset, firstOffset, lastLength uint) []byte {
	var carrier, shift byte
	data := make([]byte, len(origin))
	switch offset {
	case 1:
		shift = 0x80
	case 2:
		shift = 0xc0
	default:
		panic("leftRotate: Unexpected offset.")
	}
	if lastLength < 2 {
		panic("leftRotate: Unexpected lastLength")
	}
	for index := range data {
		if index == 0 {
			carrier = (origin[index] << firstOffset) & shift
		} else {
			shifted := origin[index] & shift
			shifted >>= uint(8 - offset)
			data[index-1] |= shifted
		}
		data[index] = origin[index] << offset
		if index == len(data)-1 {
			carrierShift := 8 - lastLength
			data[index] |= carrier << carrierShift
		}
	}
	return data
}

//Permute the original data with the input table
//Index in the table should starts from 1
func permute(origin, table []byte) []byte {
	res := make([]byte, len(table)/8)
	for index, val := range table {
		byteIndex := (val - 1) / 8
		byteOffset := (val - 1) % 8
		permuteIndex := index / 8
		permuteOffset := byte(index % 8)
		target := (origin[byteIndex] << byteOffset) & 0x80
		res[permuteIndex] |= target >> permuteOffset
	}
	return res
}

//Initial permute using IP table
func initialPermute(block []byte) []byte {
	return permute(block, initialPermuteTable[:])
}

//Fill in a block that is shorter than the block size
//with the added byte being the padding length needed.
func pkcs7Padding(blockData *[]byte) error {
	if len(*blockData) > BLOCK_SIZE {
		return errors.New("input data is longer than BLOCK_SIZE")
	}
	PaddingBytes := BLOCK_SIZE - len(*blockData)
	*blockData = append(*blockData, bytes.Repeat([]byte{byte(PaddingBytes)}, PaddingBytes)...)
	return nil
}

//Delete n bytes from the end of the input blocks where n equals
// to the last byte of the input block.
func pkcs7Unpadding(blockData *[]byte) error {
	if len(*blockData) > BLOCK_SIZE {
		return errors.New("input data is longer than BLOCK_SIZE")
	}
	UnpaddingSize := (*blockData)[len(*blockData)-1]
	if UnpaddingSize > 8 {
		return nil
	}
	unpadFlag := true
	for i := byte(0); i < UnpaddingSize; i++ {
		if (*blockData)[len(*blockData)-1] != UnpaddingSize {
			unpadFlag = false
		}
	}
	if unpadFlag {
		*blockData = (*blockData)[:len(*blockData)-int(UnpaddingSize)]
	}
	return nil
}

//get the bit corresponding to the index from the byte array
//returns the bit as the first element of the returned byte
func getBit(arr []byte, index uint) byte {
	arrIndex := index / 8
	offset := index % 8
	return (arr[arrIndex] << offset) & 0x80
}

//Feistel Function
func feistel(right []byte, key [6]byte) []byte {
	expanded := permute(right, eExpandTable[:])
	res := make([]byte, 4)
	for index := range key {
		expanded[index] ^= key[index]
	}
	for i := 0; i < 8; i++ {
		startIndex := uint(i * 6)
		row := (getBit(expanded, startIndex) >> 7) | (getBit(expanded, startIndex+5) >> 6)
		col := (getBit(expanded, startIndex+1) >> 4) | (getBit(expanded, startIndex+2) >> 5) |
			(getBit(expanded, startIndex+3) >> 6) | (getBit(expanded, startIndex+4) >> 7)
		item := sBoxes[i][row][col]
		res[i/2] |= item >> uint((i%2)*4)
	}

	return permute(res, feistelPTable[:])
}
