package testutils

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// MockTransporter is a struct for mock http response
type MockTransporter struct {
	StatusCode int
	Body       []byte
	Method     string
	URL        *url.URL
	Delay      time.Duration
	Error      error
}

// RoundTrip is used to crate a mock http response
func (m *MockTransporter) RoundTrip(req *http.Request) (*http.Response, error) {
	// If Delay field is set, delay response in m.Delay
	time.Sleep(m.Delay)

	readcloser := ioutil.NopCloser(bytes.NewBuffer(m.Body))
	return &http.Response{
		Status:     fmt.Sprintf("%d %s", m.StatusCode, http.StatusText(m.StatusCode)),
		StatusCode: m.StatusCode,
		Body:       readcloser,
		Request: &http.Request{
			URL:    m.URL,
			Method: m.Method,
		},
	}, m.Error
}
