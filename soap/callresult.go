package soap

import (
	"net/http"
	"time"
)

type CallContent struct {
	Header http.Header
	Body   string
}

type CallResult struct {
	RequestURL      string
	StatusCode      int
	RequestContent  CallContent
	ResponseContent CallContent
	InvokeAt        time.Time
	ReturnAt        time.Time
	DecodedAt       time.Time
}
