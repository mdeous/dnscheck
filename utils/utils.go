package utils

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/mdeous/dnscheck/log"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

func ReadLines(file string, output chan<- string) {
	defer close(output)
	fd, err := os.Open(file)
	if err != nil {
		log.Fatal("Unable to read input file %s: %v", file, err)
	}
	defer func(fd *os.File) {
		err := fd.Close()
		if err != nil {
			log.Warn("Unable to close input file %s: %v", file, err)
		}
	}(fd)
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := strings.Trim(scanner.Text(), " \r\n")
		if len(line) > 0 {
			output <- line
		}
	}
	err = scanner.Err()
	if err != nil {
		log.Fatal("Error while reading input file %s: %v", file, err)
	}
}

func HttpGet(url string, timeout uint) (string, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("unable to query %s: %v", url, err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read response body from %s: %v", url, err)
	}
	return string(body), nil
}
