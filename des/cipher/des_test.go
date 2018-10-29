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


var encryptedCBCResult = [][]byte{
	{154, 133, 165, 51, 228, 172, 3, 100, 247, 122, 226, 28, 166, 205, 32, 32, 100, 133, 98, 192, 0, 249, 11, 201, 136, 242, 5, 30, 183, 226, 95, 12, 231, 209, 144, 40, 42, 95, 83, 60, 99, 84, 255, 171, 200, 39, 106, 204, 15, 18, 97, 93, 150, 135, 150, 244, 153, 142, 15, 75, 213, 249, 29, 175, 213, 96, 6, 148, 224, 194, 172, 22},
	{58, 5, 5, 251, 199, 31, 187, 196, 167, 26, 178, 131, 62, 174, 89, 48, 196, 53, 194, 6, 171, 89, 71, 233, 216, 130, 85, 179, 164, 185, 97, 156, 71, 65, 48, 146, 0, 223, 223, 92, 51, 20, 175, 12, 23, 75, 105, 92, 175, 162, 193, 101, 120, 61, 238, 84, 201, 238, 95, 173, 12, 185, 231, 127, 117, 224, 166, 7, 74, 121, 111, 182},
	{160, 163, 161, 218, 165, 133, 238, 38, 147, 2, 145, 22, 131, 197, 196, 203, 241, 179, 240, 213, 155, 102, 23, 149, 96, 241, 98, 118, 184, 7, 198, 120, 2, 80, 3, 185, 169, 129, 144, 166, 147, 50, 145, 113, 197, 203, 152, 139, 241, 131, 240, 253, 210, 106, 72, 213, 96, 241, 98, 207, 53, 3, 67, 120, 2, 80, 3, 145, 227, 50, 177, 247},
	{0, 19, 1, 161, 72, 12, 4, 70, 195, 66, 193, 85, 219, 147, 3, 27, 81, 3, 80, 75, 125, 231, 115, 53, 48, 161, 50, 201, 109, 98, 104, 168, 162, 192, 163, 135, 71, 29, 183, 198, 195, 114, 193, 221, 94, 159, 194, 219, 81, 35, 80, 151, 242, 207, 230, 245, 48, 129, 50, 177, 226, 96, 9, 232, 162, 224, 163, 45, 128, 177, 89, 23},
}

var ciphers, cbcCiphers []DesCipher

func init() {
	for _, key := range testKey {
		ci, _ := NewDesCipher(key, false)
		ciphers = append(ciphers, *ci)
	}
	for _, key := range testKey {
		ci, _ := NewDesCipher(key, true)
		cbcCiphers = append(cbcCiphers, *ci)
	}
}

func TestDesCipher_DecryptData(t *testing.T) {
	for i := range encryptedResult {
		des := ciphers[i%2]
		text := testOriginData[i/2]
		decryptedText, _ := des.DecryptData(encryptedResult[i])
		if len(text) != len(decryptedText) {
			t.Errorf("ECB Decryption test case #%v is having a length error.", i)
		}
		for index := range decryptedText {
			if text[index] != decryptedText[index] {
				t.Errorf("ECB Decryption test case #%v is having a content error.", i)
				break
			}
		}
	}

	//CBC
	for i := range encryptedCBCResult {
		des := cbcCiphers[i%2]
		text := testOriginData[i/2]
		decryptedText, _ := des.DecryptData(encryptedCBCResult[i])
		if len(text) != len(decryptedText) {
			t.Errorf("CBC Decryption test case #%v is having a length error.", i)
		}
		for index := range decryptedText {
			if text[index] != decryptedText[index] {
				t.Errorf("CBC Decryption test case #%v is having a content error.", i)
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
			t.Errorf("ECB Encryption test case #%v is having a length error.", i)
		}
		for index := range cipherText {
			if encryptedResult[i][index] != cipherText[index] {
				t.Errorf("ECB Encryption test case #%v is having a content error.", i)
				break
			}
		}
	}

	//CBC
	for i := range encryptedCBCResult {
		des := cbcCiphers[i%2]
		text := make([]byte, len(testOriginData[i/2]))
		copy(text, testOriginData[i/2])
		cipherText, _ := des.EncryptData(text)
		if len(cipherText) != len(encryptedCBCResult[i]) {
			t.Errorf("CBC Encryption test case #%v is having a length error.", i)
		}
		for index := range cipherText {
			if encryptedCBCResult[i][index] != cipherText[index] {
				t.Errorf("CBC Encryption test case #%v is having a content error.", i)
				break
			}
		}
	}
}


