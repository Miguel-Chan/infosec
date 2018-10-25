package main

import (
	"bufio"
	"fmt"
	"github.com/Miguel-Chan/infosec/des/cipher"
	"io"
	"os"
	"strings"
)

func main() {
	var filename, keyStr string
	encryptMode := true
	errStr := fmt.Sprintf("Usage: %v {encrypt|decrypt} [filename]", os.Args[0])

	if len(os.Args) == 1 {
		fmt.Fprintln(os.Stderr, errStr)
		os.Exit(1)
	} else {
		switch strings.ToLower(os.Args[1]) {
		case "-h", "--help", "help":
			fmt.Fprintln(os.Stderr, errStr)
			os.Exit(0)
		case "encrypt", "e":
			encryptMode = true
		case "decrypt", "d":
			encryptMode = false
		default:
			fmt.Fprintf(os.Stderr, "Unknown argument: %v\n", os.Args[1])
			fmt.Fprintln(os.Stderr, errStr)
			os.Exit(1)
		}
		if len(os.Args) > 2 {
			filename = os.Args[2]
		}
	}

	fmt.Print("Enter your encryption key: ")
	fmt.Scanln(&keyStr)
	key := []byte(keyStr)

	if len(key) != 8 {
		fmt.Fprintln(os.Stderr, "Error: key length should be of size 8.")
		os.Exit(1)
	}

	var reader io.Reader
	if filename != "" {
		file, err := os.Open(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Using file: %v\n", filename)
		reader = file
	} else {
		fmt.Println("Enter your messages below, use EOF to mark the end.")
		reader = os.Stdin
	}
	bufReader := bufio.NewReader(reader)
	input := make([]byte, 0)

	for {
		b, err := bufReader.ReadByte()
		if err == io.EOF {
			break
		}
		input = append(input, b)
	}

	ci, err := cipher.NewDesCipher(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err)
		os.Exit(1)
	}

	var output []byte
	if encryptMode {
		output, err = ci.EncryptData(input)
	} else {
		output, err = ci.DecryptData(input)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err)
		os.Exit(1)
	}

	fmt.Println("***Encrypted/Decrypted Data are Shown Below***")
	if encryptMode {
		fmt.Printf("%v\n", output)
		outFile, err := os.Create("EncryptedData")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating file: %v", err)
			os.Exit(1)
		}
		outFile.Write(output)
	} else {
		fmt.Printf("%v\n", string(output))
		outFile, err := os.Create("DecryptedData.txt")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating file: %v", err)
			os.Exit(1)
		}
		outFile.Write(output)
	}

}
