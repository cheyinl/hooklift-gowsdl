package soap

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/ucarion/c14n"
)

type SOAPEncoder interface {
	Encode(v interface{}) error
	Flush() error
}

type SOAPDecoder interface {
	Decode(v interface{}) error
}

type SOAPEnvelopeResponse struct {
	XMLName     xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Header      *SOAPHeaderResponse
	Body        SOAPBodyResponse
	Attachments []MIMEMultipartAttachment `xml:"attachments,omitempty"`
}

// const SOAPMIMEType = "text/xml; charset=utf-8"
// const SOAPMIMEType = "application/xml; charset=utf-8"
// const SOAPMIMEType = "application/soap+xml; charset=utf-8"
const SOAPMIMEType = "text/xml"

type SOAPEnvelope struct {
	XMLName xml.Name `xml:"SOAP-ENV:Envelope"`
	XmlNS   string   `xml:"xmlns:SOAP-ENV,attr"`

	Header *SOAPHeader
	Body   SOAPBody
}

type SOAPHeader struct {
	XMLName xml.Name `xml:"SOAP-ENV:Header"`

	Headers []interface{}
}
type SOAPHeaderResponse struct {
	XMLName xml.Name `xml:"Header"`

	Headers []interface{}
}

type SOAPBody struct {
	XMLName xml.Name `xml:"SOAP-ENV:Body"`

	// XMLNSWsu is the SOAP WS-Security utility namespace.
	XMLNSWsu string `xml:"xmlns:wsu,attr,omitempty"`
	// ID is a body ID used during WS-Security signing.
	ID string `xml:"wsu:Id,attr,omitempty"`

	Content interface{} `xml:",omitempty"`

	// faultOccurred indicates whether the XML body included a fault;
	// we cannot simply store SOAPFault as a pointer to indicate this, since
	// fault is initialized to non-nil with user-provided detail type.
	faultOccurred bool
	Fault         *SOAPFault `xml:",omitempty"`
}

type SOAPBodyResponse struct {
	XMLName xml.Name `xml:"Body"`

	Content interface{} `xml:",omitempty"`

	// faultOccurred indicates whether the XML body included a fault;
	// we cannot simply store SOAPFault as a pointer to indicate this, since
	// fault is initialized to non-nil with user-provided detail type.
	faultOccurred bool
	Fault         *SOAPFault `xml:",omitempty"`
}

type MIMEMultipartAttachment struct {
	Name string
	Data []byte
}

// UnmarshalXML unmarshals SOAPBody xml
func (b *SOAPBodyResponse) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	if b.Content == nil {
		return xml.UnmarshalError("Content must be a pointer to a struct")
	}

	var (
		token    xml.Token
		err      error
		consumed bool
	)

Loop:
	for {
		if token, err = d.Token(); err != nil {
			return err
		}

		if token == nil {
			break
		}

		switch se := token.(type) {
		case xml.StartElement:
			if consumed {
				return xml.UnmarshalError("Found multiple elements inside SOAP body; not wrapped-document/literal WS-I compliant")
			} else if se.Name.Space == "http://schemas.xmlsoap.org/soap/envelope/" && se.Name.Local == "Fault" {
				b.Content = nil

				b.faultOccurred = true
				err = d.DecodeElement(b.Fault, &se)
				if err != nil {
					return err
				}

				consumed = true
			} else {
				if err = d.DecodeElement(b.Content, &se); err != nil {
					return err
				}

				consumed = true
			}
		case xml.EndElement:
			break Loop
		}
	}

	return nil
}

func (b *SOAPBody) ErrorFromFault() error {
	if b.faultOccurred {
		return b.Fault
	}
	b.Fault = nil
	return nil
}

func (b *SOAPBodyResponse) ErrorFromFault() error {
	if b.faultOccurred {
		return b.Fault
	}
	b.Fault = nil
	return nil
}

type DetailContainer struct {
	Detail interface{}
}

type FaultError interface {
	// ErrorString should return a short version of the detail as a string,
	// which will be used in place of <faultstring> for the error message.
	// Set "HasData()" to always return false if <faultstring> error
	// message is preferred.
	ErrorString() string
	// HasData indicates whether the composite fault contains any data.
	HasData() bool
}

type SOAPFault struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`

	Code   string     `xml:"faultcode,omitempty"`
	String string     `xml:"faultstring,omitempty"`
	Actor  string     `xml:"faultactor,omitempty"`
	Detail FaultError `xml:"detail,omitempty"`
}

func (f *SOAPFault) Error() string {
	if f.Detail != nil && f.Detail.HasData() {
		return f.Detail.ErrorString()
	}
	return f.String
}

// HTTPError is returned whenever the HTTP request to the server fails
type HTTPError struct {
	//StatusCode is the status code returned in the HTTP response
	StatusCode int
	//ResponseBody contains the body returned in the HTTP response
	ResponseBody []byte
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP Status %d: %s", e.StatusCode, string(e.ResponseBody))
}

const (
	// Predefined WSS namespaces to be used in
	WssNsWSSE           string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	WssNsWSU            string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	WssNsType           string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
	mtomContentType     string = `multipart/related; start-info="application/soap+xml"; type="application/xop+xml"; boundary="%s"`
	XmlNsSoapEnv        string = "http://schemas.xmlsoap.org/soap/envelope/"
	WssEncodeTypeBase64        = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
	WssValueTypeX509v3         = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
	NsXMLDSig                  = "http://www.w3.org/2000/09/xmldsig#"
	NsXMLExcC14N               = "http://www.w3.org/2001/10/xml-exc-c14n#"
)

type WSSSecurityHeader struct {
	XMLName   xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ wsse:Security"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`

	MustUnderstand string `xml:"mustUnderstand,attr,omitempty"`

	Token *WSSUsernameToken `xml:",omitempty"`
}

type WSSUsernameToken struct {
	XMLName   xml.Name `xml:"wsse:UsernameToken"`
	XmlNSWsu  string   `xml:"xmlns:wsu,attr"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`

	Id string `xml:"wsu:Id,attr,omitempty"`

	Username *WSSUsername `xml:",omitempty"`
	Password *WSSPassword `xml:",omitempty"`
}

type WSSUsername struct {
	XMLName   xml.Name `xml:"wsse:Username"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`

	Data string `xml:",chardata"`
}

type WSSPassword struct {
	XMLName   xml.Name `xml:"wsse:Password"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`
	XmlNSType string   `xml:"Type,attr"`

	Data string `xml:",chardata"`
}

// NewWSSSecurityHeader creates WSSSecurityHeader instance
func NewWSSSecurityHeader(user, pass, tokenID, mustUnderstand string) *WSSSecurityHeader {
	hdr := &WSSSecurityHeader{XmlNSWsse: WssNsWSSE, MustUnderstand: mustUnderstand}
	hdr.Token = &WSSUsernameToken{XmlNSWsu: WssNsWSU, XmlNSWsse: WssNsWSSE, Id: tokenID}
	hdr.Token.Username = &WSSUsername{XmlNSWsse: WssNsWSSE, Data: user}
	hdr.Token.Password = &WSSPassword{XmlNSWsse: WssNsWSSE, XmlNSType: WssNsType, Data: pass}
	return hdr
}

type basicAuth struct {
	Login    string
	Password string
}

type options struct {
	tlsCfg           *tls.Config
	auth             *basicAuth
	timeout          time.Duration
	contimeout       time.Duration
	tlshshaketimeout time.Duration
	client           HTTPClient
	userAgent        string
	httpHeaders      map[string]string
	mtom             bool
	mma              bool
}

var defaultOptions = options{
	timeout:          time.Duration(30 * time.Second),
	contimeout:       time.Duration(90 * time.Second),
	tlshshaketimeout: time.Duration(15 * time.Second),
	userAgent:        "gowsdl/0.1",
}

// A Option sets options such as credentials, tls, etc.
type Option func(*options)

// WithHTTPClient is an Option to set the HTTP client to use
// This cannot be used with WithTLSHandshakeTimeout, WithTLS,
// WithTimeout options
func WithHTTPClient(c HTTPClient) Option {
	return func(o *options) {
		o.client = c
	}
}

// WithTLSHandshakeTimeout is an Option to set default tls handshake timeout
// This option cannot be used with WithHTTPClient
func WithTLSHandshakeTimeout(t time.Duration) Option {
	return func(o *options) {
		o.tlshshaketimeout = t
	}
}

// WithRequestTimeout is an Option to set default end-end connection timeout
// This option cannot be used with WithHTTPClient
func WithRequestTimeout(t time.Duration) Option {
	return func(o *options) {
		o.contimeout = t
	}
}

// WithBasicAuth is an Option to set BasicAuth
func WithBasicAuth(login, password string) Option {
	return func(o *options) {
		o.auth = &basicAuth{Login: login, Password: password}
	}
}

// WithTLS is an Option to set tls config
// This option cannot be used with WithHTTPClient
func WithTLS(tls *tls.Config) Option {
	return func(o *options) {
		o.tlsCfg = tls
	}
}

// WithTimeout is an Option to set default HTTP dial timeout
func WithTimeout(t time.Duration) Option {
	return func(o *options) {
		o.timeout = t
	}
}

// WithUserAgent is an Option to set User-Agent header value
func WithUserAgent(userAgent string) Option {
	return func(o *options) {
		o.userAgent = userAgent
	}
}

// WithHTTPHeaders is an Option to set global HTTP headers for all requests
func WithHTTPHeaders(headers map[string]string) Option {
	return func(o *options) {
		o.httpHeaders = headers
	}
}

// WithMTOM is an Option to set Message Transmission Optimization Mechanism
// MTOM encodes fields of type Binary using XOP.
func WithMTOM() Option {
	return func(o *options) {
		o.mtom = true
	}
}

// WithMIMEMultipartAttachments is an Option to set SOAP MIME Multipart attachment support.
// Use Client.AddMIMEMultipartAttachment to add attachments of type MIMEMultipartAttachment to your SOAP request.
func WithMIMEMultipartAttachments() Option {
	return func(o *options) {
		o.mma = true
	}
}

func makeDefaultClient(opts *options) HTTPClient {
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: opts.tlsCfg,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: opts.timeout}
			return d.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout:   opts.tlshshaketimeout,
		ExpectContinueTimeout: time.Second * 2,
	}
	return &http.Client{
		Timeout:   opts.contimeout,
		Transport: tr,
	}
}

// Client is soap client
type Client struct {
	url         string
	opts        *options
	headers     []interface{}
	attachments []MIMEMultipartAttachment

	wssPrivateKey  *rsa.PrivateKey
	wssCertBlobB64 string
}

// HTTPClient is a client which can make HTTP requests
// An example implementation is net/http.Client
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// NewClient creates new SOAP client instance
func NewClient(url string, opt ...Option) *Client {
	opts := defaultOptions
	for _, o := range opt {
		o(&opts)
	}
	if opts.client == nil {
		opts.client = makeDefaultClient(&opts)
	}
	return &Client{
		url:  url,
		opts: &opts,
	}
}

func (s *Client) SetWSSHeaderSigningKey(wssPrivateKey *rsa.PrivateKey, wssCertBlobBase64 string) {
	s.wssPrivateKey = wssPrivateKey
	s.wssCertBlobB64 = wssCertBlobBase64
}

// AddHeader adds envelope header
// For correct behavior, every header must contain a `XMLName` field.  Refer to #121 for details
func (s *Client) AddHeader(header interface{}) {
	s.headers = append(s.headers, header)
}

// AddMIMEMultipartAttachment adds an attachment to the client that will be sent only if the
// WithMIMEMultipartAttachments option is used
func (s *Client) AddMIMEMultipartAttachment(attachment MIMEMultipartAttachment) {
	s.attachments = append(s.attachments, attachment)
}

// SetHeaders sets envelope headers, overwriting any existing headers.
// For correct behavior, every header must contain a `XMLName` field.  Refer to #121 for details
func (s *Client) SetHeaders(headers ...interface{}) {
	s.headers = headers
}

// CallContext performs HTTP POST request with a context
func (s *Client) CallContext(ctx context.Context, soapAction string, request, response interface{}) (*CallResult, error) {
	return s.call(ctx, soapAction, request, response, nil, nil)
}

// Call performs HTTP POST request.
// Note that if the server returns a status code >= 400, a HTTPError will be returned
func (s *Client) Call(soapAction string, request, response interface{}) (*CallResult, error) {
	return s.call(context.Background(), soapAction, request, response, nil, nil)
}

// CallContextWithAttachmentsAndFaultDetail performs HTTP POST request.
// Note that if SOAP fault is returned, it will be stored in the error.
// On top the attachments array will be filled with attachments returned from the SOAP request.
func (s *Client) CallContextWithAttachmentsAndFaultDetail(ctx context.Context, soapAction string, request,
	response interface{}, faultDetail FaultError, attachments *[]MIMEMultipartAttachment) (*CallResult, error) {
	return s.call(ctx, soapAction, request, response, faultDetail, attachments)
}

// CallContextWithFault performs HTTP POST request.
// Note that if SOAP fault is returned, it will be stored in the error.
func (s *Client) CallContextWithFaultDetail(ctx context.Context, soapAction string, request, response interface{}, faultDetail FaultError) (*CallResult, error) {
	return s.call(ctx, soapAction, request, response, faultDetail, nil)
}

// CallWithFaultDetail performs HTTP POST request.
// Note that if SOAP fault is returned, it will be stored in the error.
// the passed in fault detail is expected to implement FaultError interface,
// which allows to condense the detail into a short error message.
func (s *Client) CallWithFaultDetail(soapAction string, request, response interface{}, faultDetail FaultError) (*CallResult, error) {
	return s.call(context.Background(), soapAction, request, response, faultDetail, nil)
}

func (s *Client) makeWSSESecurityHeader(envelope *SOAPEnvelope) (securityHeader *security, err error) {
	bodyWssRefId := makeSecureId("B-")
	envelope.Body.ID = bodyWssRefId
	buf, err := xml.Marshal(&envelope.Body)
	if nil != err {
		return
	}
	dec := xml.NewDecoder(bytes.NewReader(buf))
	cout, err := c14n.Canonicalize(dec)
	if nil != err {
		return
	}
	contentDigest := sha256.Sum256(cout)
	encContentDigest := base64.StdEncoding.EncodeToString(contentDigest[:])
	signedInfo := signedInfo{
		XMLNS: NsXMLDSig,
		CanonicalizationMethod: canonicalizationMethod{
			Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
			InclusiveNamespaces: inclusiveNamespaces{
				XMLNS:      NsXMLExcC14N,
				PrefixList: "SOAP-ENV",
			},
		},
		SignatureMethod: signatureMethod{
			Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		},
		Reference: signatureReference{
			URI: "#" + bodyWssRefId,
			Transforms: transforms{
				Transform: transform{
					Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
					// InclusiveNamespaces: inclusiveNamespaces{},
				},
			},
			DigestMethod: digestMethod{
				Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
			},
			DigestValue: digestValue{
				Value: encContentDigest,
			},
		},
	}
	if buf, err = xml.Marshal(signedInfo); nil != err {
		return
	}
	dec = xml.NewDecoder(bytes.NewReader(buf))
	if cout, err = c14n.Canonicalize(dec); nil != err {
		return
	}
	signedInfoDigest := sha256.Sum256(cout)
	sigValue, err := rsa.SignPKCS1v15(rand.Reader, s.wssPrivateKey, crypto.SHA256, signedInfoDigest[:])
	if nil != err {
		return
	}
	encSigValue := base64.StdEncoding.EncodeToString(sigValue)
	secTokenWsuRefId := makeSecureId("X509CERT-")
	secTokenRefId := makeSecureId("SECTOK-")
	keyInfoRefId := makeSecureId("KINF-")
	securityHeader = &security{
		XMLNS:              WssNsWSSE,
		SOAPMustUnderstand: 1,
		BinarySecurityToken: binarySecurityToken{
			XMLNS:        WssNsWSU,
			WsuID:        secTokenWsuRefId,
			EncodingType: WssEncodeTypeBase64,
			ValueType:    WssValueTypeX509v3,
			Value:        s.wssCertBlobB64,
		},
		Signature: signature{
			XMLNS:          NsXMLDSig,
			SignedInfo:     signedInfo,
			SignatureValue: encSigValue,
			KeyInfo: keyInfo{
				KeyInfoID: keyInfoRefId,
				SecurityTokenReference: securityTokenReference{
					XMLNS: WssNsWSU,
					StrID: secTokenRefId,
					Reference: strReference{
						ValueType: WssValueTypeX509v3,
						URI:       "#" + secTokenWsuRefId,
					},
				},
			},
		},
	}
	return
}

func (s *Client) call(ctx context.Context, soapAction string, request, response interface{}, faultDetail FaultError,
	retAttachments *[]MIMEMultipartAttachment) (*CallResult, error) {
	// SOAP envelope capable of namespace prefixes
	envelope := SOAPEnvelope{
		XmlNS: XmlNsSoapEnv,
	}
	envelope.Body.XMLNSWsu = WssNsWSU
	envelope.Body.Content = request
	soapHeaders := make([]interface{}, 1, 1+len(s.headers))
	secHeader, err := s.makeWSSESecurityHeader(&envelope)
	if nil != err {
		return nil, err
	}
	soapHeaders[0] = secHeader
	if len(s.headers) > 0 {
		soapHeaders = append(soapHeaders, s.headers...)
	}
	if s.headers != nil && len(s.headers) > 0 {
		envelope.Header = &SOAPHeader{
			Headers: soapHeaders,
		}
	}
	var reqBody []byte
	var reqBoundary string
	// buffer.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>")
	if s.opts.mtom && s.opts.mma {
		return nil, fmt.Errorf("cannot use MTOM (XOP) and MMA (MIME Multipart Attachments) option at the same time")
	} else if s.opts.mtom {
		var buffer bytes.Buffer
		encoder := newMtomEncoder(&buffer)
		if err := encoder.Encode(envelope); err != nil {
			return nil, err
		}
		if err := encoder.Flush(); err != nil {
			return nil, err
		}
		reqBody = buffer.Bytes()
		reqBoundary = encoder.Boundary()
		log.Print("TRACE: 1")
	} else if s.opts.mma {
		var buffer bytes.Buffer
		encoder := newMmaEncoder(&buffer, s.attachments)
		if err := encoder.Encode(envelope); err != nil {
			return nil, err
		}
		if err := encoder.Flush(); err != nil {
			return nil, err
		}
		reqBody = buffer.Bytes()
		reqBoundary = encoder.Boundary()
		log.Print("TRACE: 2")
	} else {
		/*
			buf, err := xml.Marshal(envelope)
			if nil != err {
				return nil, err
			}
			dec := xml.NewDecoder(bytes.NewReader(buf))
			reqBody, err = c14n.Canonicalize(dec)
			if nil != err {
				return nil, err
			}
		*/
		reqBody, err = xml.Marshal(envelope)
		if nil != err {
			return nil, fmt.Errorf("marshal envelop failed: %w", err)
		}
		log.Printf("*** TRACE: 3: %s", string(reqBody))
	}

	invokeResult := CallResult{
		RequestURL: s.url,
		RequestContent: CallContent{
			Body: string(reqBody),
		},
	}
	req, err := http.NewRequest("POST", s.url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	if s.opts.auth != nil {
		req.SetBasicAuth(s.opts.auth.Login, s.opts.auth.Password)
	}

	req = req.WithContext(ctx)

	if s.opts.mtom {
		req.Header.Add("Content-Type", fmt.Sprintf(mtomContentType, reqBoundary))
	} else if s.opts.mma {
		req.Header.Add("Content-Type", fmt.Sprintf(mmaContentType, reqBoundary))
	} else {
		req.Header.Add("Content-Type", SOAPMIMEType)
	}
	// req.Header.Add("SOAPAction", soapAction)
	req.Header.Set("User-Agent", s.opts.userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Expect", "100-continue")
	if s.opts.httpHeaders != nil {
		for k, v := range s.opts.httpHeaders {
			req.Header.Set(k, v)
		}
	}
	req.Close = true

	client := s.opts.client
	if client == nil {
		tr := &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: s.opts.tlsCfg,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := net.Dialer{Timeout: s.opts.timeout}
				return d.DialContext(ctx, network, addr)
			},
			TLSHandshakeTimeout:   s.opts.tlshshaketimeout,
			ExpectContinueTimeout: time.Second * 2,
		}
		client = &http.Client{Timeout: s.opts.contimeout, Transport: tr}
	}
	invokeResult.RequestContent.Header = req.Header.Clone()

	invokeResult.InvokeAt = time.Now()
	res, err := client.Do(req)
	if err != nil {
		invokeResult.ReturnAt = time.Now()
		return &invokeResult, err
	}
	defer res.Body.Close()
	respBody, err := ioutil.ReadAll(res.Body)
	invokeResult.ReturnAt = time.Now()
	invokeResult.ResponseContent = CallContent{
		Header: res.Header.Clone(),
		Body:   string(respBody),
	}
	invokeResult.StatusCode = res.StatusCode
	if res.StatusCode >= 400 {
		return &invokeResult, &HTTPError{
			StatusCode:   res.StatusCode,
			ResponseBody: respBody,
		}
	}
	if nil != err {
		return &invokeResult, fmt.Errorf("cannot read all content from http body: %w", err)
	}

	// xml Decoder (used with and without MTOM) cannot handle namespace prefixes (yet),
	// so we have to use a namespace-less response envelope
	respEnvelope := new(SOAPEnvelopeResponse)
	respEnvelope.Body = SOAPBodyResponse{
		Content: response,
		Fault: &SOAPFault{
			Detail: faultDetail,
		},
	}

	mtomBoundary, err := getMtomHeader(res.Header.Get("Content-Type"))
	if err != nil {
		return &invokeResult, err
	}

	var mmaBoundary string
	if s.opts.mma {
		mmaBoundary, err = getMmaHeader(res.Header.Get("Content-Type"))
		if err != nil {
			return &invokeResult, err
		}
	}

	var dec SOAPDecoder
	if mtomBoundary != "" {
		dec = newMtomDecoder(bytes.NewReader(respBody), mtomBoundary)
	} else if mmaBoundary != "" {
		dec = newMmaDecoder(bytes.NewReader(respBody), mmaBoundary)
	} else {
		dec = xml.NewDecoder(bytes.NewReader(respBody))
	}

	if err := dec.Decode(respEnvelope); err != nil {
		return &invokeResult, fmt.Errorf("cannot decode: %w", err)
	}
	invokeResult.DecodedAt = time.Now()

	if respEnvelope.Attachments != nil {
		*retAttachments = respEnvelope.Attachments
	}
	return &invokeResult, respEnvelope.Body.ErrorFromFault()
}
