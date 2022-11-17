package soap

import (
	"encoding/xml"
)

type binarySecurityToken struct {
	XMLName xml.Name `xml:"wsse:BinarySecurityToken"`
	XMLNS   string   `xml:"xmlns:wsu,attr"`

	WsuID string `xml:"wsu:Id,attr"`

	EncodingType string `xml:"EncodingType,attr"`
	ValueType    string `xml:"ValueType,attr"`

	Value string `xml:",chardata"`
}

type inclusiveNamespaces struct {
	XMLName    xml.Name `xml:"http://www.w3.org/2001/10/xml-exc-c14n# InclusiveNamespaces"`
	PrefixList string   `xml:"PrefixList,attr"`
}

type canonicalizationMethod struct {
	XMLName             xml.Name `xml:"CanonicalizationMethod"`
	Algorithm           string   `xml:"Algorithm,attr"`
	InclusiveNamespaces inclusiveNamespaces
}

type signatureMethod struct {
	XMLName   xml.Name `xml:"SignatureMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type digestMethod struct {
	XMLName   xml.Name `xml:"DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type digestValue struct {
	XMLName xml.Name `xml:"DigestValue"`
	Value   string   `xml:",chardata"`
}

type transform struct {
	XMLName             xml.Name `xml:"Transform"`
	Algorithm           string   `xml:"Algorithm,attr"`
	InclusiveNamespaces inclusiveNamespaces
}

type transforms struct {
	XMLName   xml.Name `xml:"Transforms"`
	Transform transform
}

type signatureReference struct {
	XMLName xml.Name `xml:"Reference"`
	URI     string   `xml:"URI,attr"`

	Transforms transforms

	DigestMethod digestMethod
	DigestValue  digestValue
}

type signedInfo struct {
	XMLName xml.Name `xml:"SignedInfo"`
	XMLNS   string   `xml:"xmlns,attr"`

	CanonicalizationMethod canonicalizationMethod
	SignatureMethod        signatureMethod
	Reference              signatureReference
}

type strReference struct {
	XMLName   xml.Name `xml:"wsse:Reference"`
	ValueType string   `xml:"ValueType,attr"`
	URI       string   `xml:"URI,attr"`
}

type securityTokenReference struct {
	XMLName xml.Name `xml:"wsse:SecurityTokenReference"`
	XMLNS   string   `xml:"xmlns:wsu,attr"`

	StrID string `xml:"wsu:Id,attr"`

	Reference strReference
}

type keyInfo struct {
	XMLName xml.Name `xml:"KeyInfo"`

	KeyInfoID string `xml:"Id,attr"`

	SecurityTokenReference securityTokenReference
}

type signature struct {
	XMLName xml.Name `xml:"Signature"`
	XMLNS   string   `xml:"xmlns,attr"`

	SignedInfo     signedInfo
	SignatureValue string `xml:"SignatureValue"`
	KeyInfo        keyInfo
}

type security struct {
	XMLName xml.Name `xml:"wsse:Security"`
	XMLNS   string   `xml:"xmlns:wsse,attr"`

	SOAPMustUnderstand int `xml:"SOAP-ENV:mustUnderstand,attr"`

	BinarySecurityToken binarySecurityToken
	Signature           signature
}
