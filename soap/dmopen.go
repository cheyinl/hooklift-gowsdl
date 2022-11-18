package soap

import (
	"encoding/xml"
)

type DMOpenAccountRef struct {
	XMLName    xml.Name `xml:"http://gov.fema.dmopen.services/DMOPEN_EDXLDEService EdxlHeaderTypeDef"`
	LogonUser  string   `xml:"logonUser"`
	LogonCogId string   `xml:"logonCogId"`
	SenderInfo string   `xml:"senderInfo"`
}
