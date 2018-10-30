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
	silentMode := false
	encryptMode := true
	cbcMode := false
	errStr := fmt.Sprintf("Usage: %v {encrypt|decrypt} [-s|--silent] [-cbc(default ecb mode)] [{-i|--input} filename]", os.Args[0])

	if len(os.Args) == 1 {
		fmt.Fprintln(os.Stderr, errStr)
		os.Exit(1)
	} else {
		for i := 1; i < len(os.Args); i++ {
			switch strings.ToLower(os.Args[i]) {
			case "-h", "--help", "help":
				fmt.Fprintln(os.Stderr, errStr)
				os.Exit(0)
			case "encrypt", "e":
				encryptMode = true
			case "decrypt", "d":
				encryptMode = false
			case "-s", "--silent":
				silentMode = true
			case "-cbc":
				cbcMode = true
			case "-i", "--input":
				i++
				if i == len(os.Args) {
					fmt.Fprintf(os.Stderr, "Expecting filename after %v\n", os.Args[i-1])
					fmt.Fprintln(os.Stderr, errStr)
					os.Exit(1)
				}
				filename = os.Args[i]
			default:
				fmt.Fprintf(os.Stderr, "Unknown argument: %v\n", os.Args[i])
				fmt.Fprintln(os.Stderr, errStr)
				os.Exit(1)
			}
		}
	}

	if encryptMode {
		fmt.Println("***Encryption Mode***")
	} else {
		fmt.Println("***Decryption Mode***")
		if filename == "" {
			fmt.Println("You must specify a file for decryption!")
			os.Exit(1)
		}
	}
	if cbcMode {
		fmt.Println("Processing with CBC mode.")
	} else {
		fmt.Println("Processing with ECB mode.")
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

	ci, err := cipher.NewDesCipher(key, cbcMode)
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

	if !silentMode {
		fmt.Println("***Encrypted/Decrypted Data are Shown Below***")
	}
	if encryptMode {
		if !silentMode {
			fmt.Printf("%v\n", output)
		}

		outFile, err := os.Create("EncryptedData")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating file: %v", err)
			os.Exit(1)
		}
		outFile.Write(output)
		println("Output has been saved to EncryptedData")
	} else {
		if !silentMode {
			fmt.Printf("%v\n", string(output))
		}
		outFile, err := os.Create("DecryptedData")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating file: %v", err)
			os.Exit(1)
		}
		outFile.Write(output)
		println("Output has been saved to DecryptedData")
	}

}
