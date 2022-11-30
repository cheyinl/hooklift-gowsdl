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
	XMLName    xml.Name `xml:"ec:InclusiveNamespaces"`
	XMLNS      string   `xml:"xmlns:ec,attr"`
	PrefixList string   `xml:"PrefixList,attr"`
}

type canonicalizationMethod struct {
	XMLName             xml.Name `xml:"ds:CanonicalizationMethod"`
	Algorithm           string   `xml:"Algorithm,attr"`
	InclusiveNamespaces inclusiveNamespaces
}

type signatureMethod struct {
	XMLName   xml.Name `xml:"ds:SignatureMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type digestMethod struct {
	XMLName   xml.Name `xml:"ds:DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type digestValue struct {
	XMLName xml.Name `xml:"ds:DigestValue"`
	Value   string   `xml:",chardata"`
}

type transform struct {
	XMLName   xml.Name `xml:"ds:Transform"`
	Algorithm string   `xml:"Algorithm,attr"`
	// InclusiveNamespaces inclusiveNamespaces
}

type transforms struct {
	XMLName   xml.Name `xml:"ds:Transforms"`
	Transform transform
}

type signatureReference struct {
	XMLName xml.Name `xml:"ds:Reference"`
	URI     string   `xml:"URI,attr"`

	Transforms transforms

	DigestMethod digestMethod
	DigestValue  digestValue
}

type signedInfo struct {
	XMLName      xml.Name `xml:"ds:SignedInfo"`
	XmlNsSoapEnv string   `xml:"xmlns:SOAP-ENV,attr,omitempty"`
	XMLNS        string   `xml:"xmlns:ds,attr"`

	CanonicalizationMethod canonicalizationMethod
	SignatureMethod        signatureMethod
	Reference              signatureReference
}

type strReference struct {
	XMLName   xml.Name `xml:"wsse:Reference"`
	URI       string   `xml:"URI,attr"`
	ValueType string   `xml:"ValueType,attr"`
}

type securityTokenReference struct {
	XMLName xml.Name `xml:"wsse:SecurityTokenReference"`
	XMLNS   string   `xml:"xmlns:wsu,attr"`

	StrID string `xml:"wsu:Id,attr"`

	Reference strReference
}

type keyInfo struct {
	XMLName xml.Name `xml:"ds:KeyInfo"`

	KeyInfoID string `xml:"Id,attr"`

	SecurityTokenReference securityTokenReference
}

type signature struct {
	XMLName xml.Name `xml:"ds:Signature"`
	XMLNS   string   `xml:"xmlns:ds,attr"`

	SigID string `xml:"Id,attr"`

	SignedInfo     signedInfo
	SignatureValue string `xml:"ds:SignatureValue"`
	KeyInfo        keyInfo
}

type security struct {
	XMLName xml.Name `xml:"wsse:Security"`
	XMLNS   string   `xml:"xmlns:wsse,attr"`

	SOAPMustUnderstand int `xml:"SOAP-ENV:mustUnderstand,attr"`

	BinarySecurityToken binarySecurityToken
	Signature           signature
}
