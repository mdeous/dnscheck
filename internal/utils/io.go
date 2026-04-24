package utils

import (
	"bufio"
	"os"
	"strings"

	"github.com/mdeous/dnscheck/internal/log"
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
		if strings.HasPrefix(line, "#") || len(line) == 0 {
			continue
		}
		output <- line
	}
	err = scanner.Err()
	if err != nil {
		log.Fatal("Error while reading input file %s: %v", file, err)
	}
}
