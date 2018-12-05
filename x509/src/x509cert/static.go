package x509cert

import "encoding/asn1"

var AlgorithmName = map[int]string {
	0:  "Unknown",
	1:  "MD2WithRSA",
	2:  "MD5WithRSA",
	3:  "SHA1WithRSA",
	4:  "SHA256WithRSA",
	5:  "SHA384WithRSA",
	6:  "SHA512WithRSA",
	7:  "DSAWithSHA1",
	8:  "DSAWithSHA256",
	9:  "ECDSAWithSHA1",
	10: "ECDSAWithSHA256",
	11: "ECDSAWithSHA384",
	12: "ECDSAWithSHA512",
	13: "SHA256WithRSAPSS",
	14: "SHA384WithRSAPSS",
	15: "SHA512WithRSAPSS",
	16: "rsaEncryption",
	17: "dsaEncryption",
	18: "EcdsaEncryption",
}


//Algorithm enum list
const (
	Unknown = iota
	MD2WithRSA
	MD5WithRSA
	SHA1WithRSA
	SHA256WithRSA
	SHA384WithRSA
	SHA512WithRSA
	DSAWithSHA1
	DSAWithSHA256
	ECDSAWithSHA1
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
	SHA256WithRSAPSS
	SHA384WithRSAPSS
	SHA512WithRSAPSS
	RsaEncryption
	DsaEncryption
	EcdsaEncryption
)

//oid list with index corresponding to the algorithm names above
var oidList = [][]int{
	{},//Unknown algorithm
	{1, 2, 840, 113549, 1, 1, 2},
	{1, 2, 840, 113549, 1, 1, 4},
	{1, 2, 840, 113549, 1, 1, 5},
	{1, 2, 840, 113549, 1, 1, 11},
	{1, 2, 840, 113549, 1, 1, 12},
	{1, 2, 840, 113549, 1, 1, 13},
	{1, 2, 840, 10040, 4, 3},
	{2, 16, 840, 1, 101, 3, 4, 3, 2},
	{1, 2, 840, 10045, 4, 1},
	{1, 2, 840, 10045, 4, 3, 2},
	{1, 2, 840, 10045, 4, 3, 3},
	{1, 2, 840, 10045, 4, 3, 4},
	{2, 16, 840, 1, 101, 3, 4, 2, 1},
	{2, 16, 840, 1, 101, 3, 4, 2, 2},
	{2, 16, 840, 1, 101, 3, 4, 2, 3},
	{1, 2, 840, 113549, 1, 1, 1}, //RSA Encrypt
	{1, 2, 840, 10040, 4, 1}, //dsa
	{1, 2, 840, 10045, 2, 1}, //ecdsa
}

var hexCharMap = map[byte]byte{
	0: '0', 1: '1', 2: '2', 3: '3', 4: '4', 5: '5', 6: '6',
	7: '7', 8: '8', 9: '9', 10: 'a', 11: 'b', 12: 'c',
	13: 'd', 14: 'e', 15: 'f',
}

//Curve OID
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

