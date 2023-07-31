package dns

import (
	_ "embed"
	"strings"
)

const maxReqPerResolver = 5

//go:embed resolvers.txt
var resolvers string

type Resolver struct {
	resolvers       []string
	current         int
	currentRequests int
}

func (r *Resolver) Get() string {
	if r.currentRequests >= maxReqPerResolver {
		r.current++
		r.currentRequests = 0
	}
	if r.current >= len(r.resolvers) {
		r.current = 0
	}
	r.currentRequests++
	return r.resolvers[r.current]
}

func NewResolver() *Resolver {
	r := &Resolver{}
	for _, line := range strings.Split(resolvers, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			r.resolvers = append(r.resolvers, line+":53")
		}
	}
	return r
}
