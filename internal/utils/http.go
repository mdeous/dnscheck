package utils

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
)

func makeHttpClient(timeout uint) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}
	return client
}

func httpGet(domain string, timeout uint) (*http.Response, error) {
	client := makeHttpClient(timeout)
	var resp *http.Response
	var err error
	for _, protocol := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", protocol, domain)
		resp, err = client.Get(url)
		if err == nil {
			return resp, nil
		}
	}
	return nil, err
}

func HttpGetBody(domain string, timeout uint) (string, error) {
	resp, err := httpGet(domain, timeout)
	if err != nil {
		return "", fmt.Errorf("unable to perform HTTP request to %s: %v", domain, err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read response body from %s: %v", domain, err)
	}
	return string(body), nil
}

func HttpGetStatus(domain string, timeout uint) (int, error) {
	resp, err := httpGet(domain, timeout)
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, nil
}
