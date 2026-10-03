package dns

import (
	_ "embed"
	"strings"
	"sync"
)

const maxReqPerResolver = 5

//go:embed resolvers.txt
var resolvers string

type Resolver struct {
	mut             sync.Mutex
	resolvers       []string
	current         int
	currentRequests int
}

func (r *Resolver) Get() string {
	r.mut.Lock()
	defer r.mut.Unlock()
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

// Next moves to the following resolver, for when the current one won't answer.
func (r *Resolver) Next() string {
	r.mut.Lock()
	defer r.mut.Unlock()
	r.current++
	if r.current >= len(r.resolvers) {
		r.current = 0
	}
	r.currentRequests = 1
	return r.resolvers[r.current]
}

func (r *Resolver) Count() int {
	r.mut.Lock()
	defer r.mut.Unlock()
	return len(r.resolvers)
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
