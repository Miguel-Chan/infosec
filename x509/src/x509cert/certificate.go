package x509cert

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type CertificateData struct {
	TBSCertificate     tbsCertificate
	SignatureAlgorithm AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type timeSpan struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Algorithm AlgorithmIdentifier
	PublicKey asn1.BitString
}

type extension struct {
	ExtnID    asn1.ObjectIdentifier
	Critical  bool `asn1:"default:false"`
	ExtnValue []byte
}

type tbsCertificate struct {
	Version         int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber    *big.Int
	Signature       AlgorithmIdentifier
	Issuer          asn1.RawValue
	Validity        timeSpan
	Subject         asn1.RawValue
	PublicKey       publicKeyInfo
	UniqueId        asn1.BitString `asn1:"optional,tag:1"`
	SubjectUniqueId asn1.BitString `asn1:"optional,tag:2"`
	Extensions      []extension    `asn1:"optional,explicit,tag:3"`
}

type CertInfo struct {
	Version            int
	Serial             *big.Int
	Signature          AlgorithmIdentifier
	Issuer             IssuerType
	Validity           timeSpan
	Subject            IssuerType
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString
	SubjectUniqueId    asn1.BitString
	Extensions         []extension
	SignatureAlgorithm AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type IssuerType struct {
	Country      string
	Province     string
	City         string
	Organization string
	Unit         string
}

func ParseIssuer(iss []byte) IssuerType {
	var issuer pkix.RDNSequence
	asn1.Unmarshal(iss, &issuer)
	var issuerName pkix.Name
	issuerName.FillFromRDNSequence(&issuer)
	return IssuerType{
		issuerName.Country[0],
		issuerName.Province[0],
		issuerName.Locality[0],
		issuerName.Organization[0],
		issuerName.OrganizationalUnit[0],
	}
}

func (cert *CertificateData) ToCertInfo() CertInfo {

	return CertInfo{
		cert.TBSCertificate.Version + 1,
		cert.TBSCertificate.SerialNumber,
		cert.TBSCertificate.Signature,
		ParseIssuer(cert.TBSCertificate.Issuer.FullBytes),
		cert.TBSCertificate.Validity,
		ParseIssuer(cert.TBSCertificate.Subject.FullBytes),
		cert.TBSCertificate.PublicKey,
		cert.TBSCertificate.UniqueId,
		cert.TBSCertificate.SubjectUniqueId,
		cert.TBSCertificate.Extensions,
		cert.SignatureAlgorithm,
		cert.SignatureValue,
	}
}

func BitStringToHex(str asn1.BitString) []byte {
	//4 bits -> one hex char
	result := make([]byte, 0, str.BitLength/4+1)
	for i := 0; i < str.BitLength; i += 4 {
		byteIndex := i / 8
		targetByte := str.Bytes[byteIndex]
		if i%8 == 0 {
			targetByte >>= 4
		} else {
			targetByte &= 0x0f
		}
		result = append(result, hexCharMap[targetByte])
	}
	return result
}

func GetAlgorithmFromID(algoID AlgorithmIdentifier) int {

	for index, val := range oidList {
		if algoID.Algorithm.Equal(val) {
			return index
		}
	}
	return Unknown
}

func GetAlgorithmFromOid(oid asn1.ObjectIdentifier) int {
	for index, val := range oidList {
		if oid.Equal(val) {
			return index
		}
	}
	return Unknown
}

func findCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	}
	return nil
}

func GetPublicKey(algoIndex int, key publicKeyInfo) interface{} {
	data := key.PublicKey.RightAlign()

	switch algoIndex {
	case RsaEncryption:
		res := new(rsa.PublicKey)
		_, err := asn1.Unmarshal(data, res)
		if err != nil {
			println(err)
		}
		return res
	case DsaEncryption:
		var p *big.Int
		asn1.Unmarshal(data, &p)
		param := new(dsa.Parameters)
		asn1.Unmarshal(key.Algorithm.Parameters.FullBytes, &param)
		return &dsa.PublicKey{
			Parameters: *param,
			Y:          p,
		}
	case EcdsaEncryption:
		namedCurveOID := new(asn1.ObjectIdentifier)
		asn1.Unmarshal(key.Algorithm.Parameters.FullBytes, namedCurveOID)
		namedCurve := findCurveFromOID(*namedCurveOID)
		if namedCurve == nil {
			return nil
		}
		x, y := elliptic.Unmarshal(namedCurve, data)
		if x == nil {
			panic("failed to unmarshal elliptic curve point")
		}
		return &ecdsa.PublicKey{
			Curve: namedCurve,
			X:     x,
			Y:     y,
		}
	default:
		return nil
	}
}
