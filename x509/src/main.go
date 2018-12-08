package main

import (
	"crypto/rsa"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"./x509cert"
)

func main() {
	der := flag.Bool("DER", false, "Parse the file with DER rules")

	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "No filename specified!\n")
		fmt.Fprintf(os.Stderr, "Usage: %v [--DER] filename\n", os.Args[0])
		os.Exit(1)
	}

	filename := os.Args[len(os.Args)-1]

	certFile, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open file %v\n", filename)
		return
	}

	certData := make([]byte, 3000)

	count, _ := certFile.Read(certData)
	certData = certData[:count]
	var decodeData []byte

	if !*der {
		block, _ := pem.Decode(certData)
		if block == nil {
			fmt.Fprintf(os.Stderr, "Fail to decode pem\n")
			return
		}

		decodeData = block.Bytes
	} else {
		decodeData = certData
	}

	var cert x509cert.CertificateData

	_, err = asn1.Unmarshal(decodeData, &cert)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Fail to parse asn1： %v\n", err)
		os.Exit(1)
	}

	info := cert.ToCertInfo()

	printCertInfo(&info)
}

func printCertInfo(info *x509cert.CertInfo) {
	fmt.Printf("Version: %v\n", info.Version)
	fmt.Printf("Serial Number: %v(%X)\n", info.Serial, info.Serial)
	fmt.Printf("Signature Algorithm: %v\n", x509cert.AlgorithmName[x509cert.GetAlgorithmFromOid(info.SignatureAlgorithm.Algorithm)])
	fmt.Printf("Issuer: \n")
	fmt.Printf("\tCountry: %v\n", info.Issuer.Country)
	fmt.Printf("\tProvince: %v\n", info.Issuer.Province)
	fmt.Printf("\tCity: %v\n", info.Issuer.City)
	fmt.Printf("\tOrganization: %v\n", info.Issuer.Organization)
	fmt.Printf("\tOrganization Unit: %v\n", info.Issuer.Unit)
	fmt.Printf("Subject: \n")
	fmt.Printf("\tCountry: %v\n", info.Subject.Country)
	fmt.Printf("\tProvince: %v\n", info.Subject.Province)
	fmt.Printf("\tCity: %v\n", info.Subject.City)
	fmt.Printf("\tOrganization: %v\n", info.Subject.Organization)
	fmt.Printf("\tOrganization Unit: %v\n", info.Subject.Unit)
	fmt.Printf("Validity:\n")
	fmt.Printf("\tNot Before: %v\n", info.Validity.NotBefore)
	fmt.Printf("\tNot After: %v\n", info.Validity.NotAfter)
	fmt.Printf("Subject Public Key Info: \n")
	fmt.Printf("\tPublic Key Algorithm: %v\n", x509cert.AlgorithmName[x509cert.GetAlgorithmFromID(info.PublicKey.Algorithm)])
	key := x509cert.GetPublicKey(x509cert.GetAlgorithmFromID(info.PublicKey.Algorithm), info.PublicKey)
	switch x509cert.GetAlgorithmFromID(info.PublicKey.Algorithm) {
	case x509cert.RsaEncryption:
		fmt.Printf("\tPublic Key: (%v bits)\n", key.(*rsa.PublicKey).N.BitLen())
		fmt.Printf("\tExponent: %v\n", key.(*rsa.PublicKey).E)
		fmt.Printf("\t%x\n", key.(*rsa.PublicKey).N)
	}

	fmt.Printf("Signature:\n\t %v\n", string(x509cert.BitStringToHex(info.SignatureValue)))
}
