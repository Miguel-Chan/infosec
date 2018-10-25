package cipher

import "testing"

var testKey = [][]byte{
	[]byte("12345678"),
	[]byte("abcdefgh"),
}

var testOriginData = [][]byte{
	[]byte("This is a test to see if this DES encryption implementation works."),
	[]byte("aaaaaaáâäaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
}

var encryptedResult = [][]byte{
	{168, 132, 150, 71, 82, 180, 144, 80, 146, 0, 184, 14, 186, 141, 40, 56, 159, 0, 179, 115, 24, 3, 190, 217, 16, 168, 148, 31, 186, 8, 49, 202, 163, 48, 154, 231, 26, 184, 74, 176, 184, 134, 159, 107, 87, 184, 68, 176, 156, 170, 158, 50, 29, 152, 44, 248, 150, 191, 157, 108, 118, 128, 171, 151, 179, 29, 9, 136, 203, 50, 53, 73},
	{168, 180, 150, 129, 80, 135, 124, 144, 146, 48, 184, 251, 188, 145, 148, 184, 159, 48, 179, 189, 213, 27, 176, 217, 16, 136, 148, 226, 118, 11, 140, 10, 163, 16, 154, 189, 91, 184, 87, 176, 184, 150, 159, 238, 218, 134, 156, 112, 156, 154, 158, 104, 20, 172, 109, 120, 150, 175, 157, 100, 52, 140, 160, 215, 179, 13, 9, 12, 11, 36, 134, 9},
	{146, 178, 146, 32, 213, 143, 126, 146, 195, 97, 195, 56, 93, 140, 254, 82, 146, 162, 146, 150, 88, 170, 223, 210, 146, 162, 146, 150, 88, 170, 223, 210, 146, 162, 146, 150, 88, 170, 223, 210, 146, 162, 146, 150, 88, 170, 223, 210, 146, 162, 146, 150, 88, 170, 223, 210, 146, 162, 146, 150, 88, 170, 223, 210, 146, 162, 146, 110, 83, 58, 87, 3},
	{146, 178, 146, 175, 26, 140, 187, 146, 195, 97, 195, 158, 151, 180, 159, 210, 146, 146, 146, 226, 19, 144, 165, 210, 146, 146, 146, 226, 19, 144, 165, 210, 146, 146, 146, 226, 19, 144, 165, 210, 146, 146, 146, 226, 19, 144, 165, 210, 146, 146, 146, 226, 19, 144, 165, 210, 146, 146, 146, 226, 19, 144, 165, 210, 146, 162, 146, 229, 214, 9, 197, 195},
}

var ciphers []DesCipher

func init() {
	for _, key := range testKey {
		ci, _ := NewDesCipher(key)
		ciphers = append(ciphers, *ci)
	}
}

func TestDesCipher_DecryptData(t *testing.T) {
	for i := range encryptedResult {
		des := ciphers[i%2]
		text := testOriginData[i/2]
		decryptedText, _ := des.DecryptData(encryptedResult[i])
		if len(text) != len(decryptedText) {
			t.Errorf("Decryption test case #%v is having a length error.", i)
		}
		for index := range decryptedText {
			if text[index] != decryptedText[index] {
				t.Errorf("Decryption test case #%v is having a content error.", i)
				break
			}
		}
	}
}

func TestDesCipher_EncryptData(t *testing.T) {
	for i := range encryptedResult {
		des := ciphers[i%2]
		text := testOriginData[i/2]
		cipherText, _ := des.EncryptData(text)
		if len(cipherText) != len(encryptedResult[i]) {
			t.Errorf("Encryption test case #%v is having a length error.", i)
		}
		for index := range cipherText {
			if encryptedResult[i][index] != cipherText[index] {
				t.Errorf("Encryption test case #%v is having a content error.", i)
				break
			}
		}
	}
}
