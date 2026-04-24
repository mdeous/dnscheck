package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/mdeous/dnscheck/checker"
	"gopkg.in/yaml.v3"
)

type nucleiMatcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part"`
	Words     []string `yaml:"words"`
	Status    []int    `yaml:"status"`
	DSL       []string `yaml:"dsl"`
	Negative  bool     `yaml:"negative"`
	Condition string   `yaml:"condition"`
}

type nucleiTpl struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string   `yaml:"name"`
		Description string   `yaml:"description"`
		Reference   []string `yaml:"reference"`
		Metadata    struct {
			FofaQuery string `yaml:"fofa-query"`
		} `yaml:"metadata"`
	} `yaml:"info"`
	HTTP []struct {
		Matchers []nucleiMatcher `yaml:"matchers"`
	} `yaml:"http"`
	DNS []struct {
		Type     string          `yaml:"type"`
		Matchers []nucleiMatcher `yaml:"matchers"`
	} `yaml:"dns"`
}

var (
	dslCnameRE   = regexp.MustCompile(`contains\(\s*host\s*,\s*"([^"]+)"\s*\)`)
	fofaCnameRE  = regexp.MustCompile(`cname="([^"]+)"`)
	// Matches " Takeover", " Takeover Detection", " Takeover - Detection",
	// " - Takeover Detection" at end of info.name (case insensitive).
	nameSuffixRE = regexp.MustCompile(`(?i)[\s\-]+takeover[\s\-]*(detection)?\s*$`)
	edgeCaseRE   = regexp.MustCompile(`(?i)edge case`)
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <nuclei-templates-repo> <output.json>\n", filepath.Base(os.Args[0]))
		os.Exit(2)
	}
	repoPath := os.Args[1]
	outPath := os.Args[2]

	globPattern := filepath.Join(repoPath, "http", "takeovers", "*.yaml")
	files, err := filepath.Glob(globPattern)
	if err != nil {
		fmt.Fprintf(os.Stderr, "glob failed: %v\n", err)
		os.Exit(1)
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "no templates found under %s\n", globPattern)
		os.Exit(1)
	}

	var fingerprints []*checker.Fingerprint
	seenIDs := map[string]bool{}
	skipped := 0
	parseErrors := 0

	for _, path := range files {
		base := filepath.Base(path)
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error %s: read failed: %v\n", base, err)
			parseErrors++
			continue
		}
		var tpl nucleiTpl
		if err := yaml.Unmarshal(data, &tpl); err != nil {
			fmt.Fprintf(os.Stderr, "error %s: yaml parse failed: %v\n", base, err)
			parseErrors++
			continue
		}
		if tpl.ID != "" && seenIDs[tpl.ID] {
			fmt.Fprintf(os.Stderr, "skip %s: duplicate id %q\n", base, tpl.ID)
			skipped++
			continue
		}
		fp, reason := convertTemplate(&tpl)
		if fp == nil {
			fmt.Fprintf(os.Stderr, "skip %s: %s\n", base, reason)
			skipped++
			continue
		}
		if tpl.ID != "" {
			seenIDs[tpl.ID] = true
		}
		fingerprints = append(fingerprints, fp)
	}

	// Deterministic output order by service name.
	sort.Slice(fingerprints, func(i, j int) bool {
		return fingerprints[i].Name < fingerprints[j].Name
	})

	out, err := json.MarshalIndent(fingerprints, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal failed: %v\n", err)
		os.Exit(1)
	}
	out = append(out, '\n')
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", outPath, err)
		os.Exit(1)
	}

	withCNames := 0
	for _, fp := range fingerprints {
		if len(fp.CNames) > 0 {
			withCNames++
		}
	}
	fmt.Fprintf(os.Stderr, "\ntotal=%d converted=%d skipped=%d parse_errors=%d with_cname=%d cname_less=%d\n",
		len(files), len(fingerprints), skipped, parseErrors, withCNames, len(fingerprints)-withCNames)
	fmt.Fprintln(os.Stderr, "note: cname_less fingerprints rely on dnscheck's fallback path at check_cname.go:165-182")
	fmt.Fprintln(os.Stderr, "      (they run against any resolving domain, matching on pattern/status)")
}

func convertTemplate(tpl *nucleiTpl) (*checker.Fingerprint, string) {
	fp := &checker.Fingerprint{
		Name:       normalizeName(tpl.Info.Name),
		Vulnerable: true,
		Status:     "Vulnerable",
		NXDomain:   false,
	}
	if edgeCaseRE.MatchString(tpl.Info.Description) {
		fp.Status = checker.EdgeCase
	}
	if n := len(tpl.Info.Reference); n > 0 {
		fp.Documentation = tpl.Info.Reference[0]
		if n > 1 {
			fp.Discussion = tpl.Info.Reference[1]
		}
	}

	// Walk all matchers once, collecting:
	//   - body-targeted word matchers (for Pattern)
	//   - the first status code (for HttpStatus)
	//   - host-targeted word matchers (explicit CNAMEs, e.g. aws-bucket)
	//   - DSL contains(host, "...") captures (e.g. github)
	//   - dns block IP targets (e.g. worksites)
	//   - fofa-query cname="..." metadata (e.g. greatpages)
	var bodyWordMatchers []nucleiMatcher
	var headerOnlyWord bool
	var sawWordMatcher bool
	var andConditionOnBody bool
	var statusCode int
	cnameSet := map[string]struct{}{}
	hasRegexMatcher := false

	addCName := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" {
			cnameSet[s] = struct{}{}
		}
	}

	for _, req := range tpl.HTTP {
		for _, m := range req.Matchers {
			switch m.Type {
			case "word":
				sawWordMatcher = true
				switch strings.ToLower(m.Part) {
				case "host":
					// Explicit CNAME list. Extract regardless of the `negative`
					// flag — nuclei often uses negative logic (e.g. aws-bucket:
					// "fire only when host is NOT one of these valid S3 CNAMEs"),
					// but the listed strings are still the service CNAMEs we
					// want dnscheck to match against a subdomain's CNAME target.
					for _, w := range m.Words {
						addCName(w)
					}
				case "header", "content_type":
					headerOnlyWord = true
				default: // "", "body", "all", "response", etc. → body-ish
					headerOnlyWord = false
					bodyWordMatchers = append(bodyWordMatchers, m)
					if strings.EqualFold(m.Condition, "and") && len(m.Words) > 1 {
						andConditionOnBody = true
					}
				}
			case "status":
				if statusCode == 0 && len(m.Status) > 0 {
					statusCode = m.Status[0]
				}
			case "dsl":
				for _, expr := range m.DSL {
					for _, match := range dslCnameRE.FindAllStringSubmatch(expr, -1) {
						if len(match) >= 2 {
							addCName(match[1])
						}
					}
				}
			case "regex":
				hasRegexMatcher = true
			}
		}
	}

	// DNS block: e.g. worksites matches A record against a literal IP. dnscheck
	// detects IP entries in CNames via net.ParseIP (check_cname.go:91).
	for _, d := range tpl.DNS {
		if !strings.EqualFold(d.Type, "A") {
			continue
		}
		for _, m := range d.Matchers {
			if m.Type == "word" && !m.Negative {
				for _, w := range m.Words {
					addCName(w)
				}
			}
		}
	}

	// fofa-query metadata may contain cname="..." (e.g. greatpages).
	if q := tpl.Info.Metadata.FofaQuery; q != "" {
		for _, match := range fofaCnameRE.FindAllStringSubmatch(q, -1) {
			if len(match) >= 2 {
				addCName(match[1])
			}
		}
	}

	// Pattern: first word of first body-targeted word matcher. Warn about drops.
	var droppedWords []string
	if len(bodyWordMatchers) > 0 {
		first := bodyWordMatchers[0].Words
		if len(first) > 0 {
			fp.Pattern = first[0]
			droppedWords = append(droppedWords, first[1:]...)
		}
		for _, extra := range bodyWordMatchers[1:] {
			droppedWords = append(droppedWords, extra.Words...)
		}
	}
	if len(droppedWords) > 0 {
		severity := "warn"
		if andConditionOnBody {
			severity = "warn-AND"
		}
		fmt.Fprintf(os.Stderr, "%s %s: dropped %d alternative word(s): %q\n",
			severity, tpl.ID, len(droppedWords), strings.Join(droppedWords, " | "))
	}

	// dnscheck's checkFingerprint uses if/else if — HttpStatus takes precedence
	// over Pattern (see checker/check_cname.go:37-68). If both are set, Pattern
	// is never evaluated. Since Pattern is almost always more distinctive than
	// a bare status code, we prefer Pattern and clear HttpStatus when both exist.
	// Rationale: a nuclei template like Sprintful has body="...deactivated" + status=200;
	// emitting status=200 would false-positive on every 200 response.
	if fp.Pattern != "" {
		fp.HttpStatus = 0
	} else {
		fp.HttpStatus = statusCode
	}

	if len(cnameSet) > 0 {
		fp.CNames = make([]string, 0, len(cnameSet))
		for c := range cnameSet {
			fp.CNames = append(fp.CNames, c)
		}
		sort.Strings(fp.CNames)
	}

	// status=200 is not distinctive. Skip if it would be the sole signal.
	if fp.Pattern == "" && fp.HttpStatus == 200 && len(fp.CNames) == 0 {
		return nil, "status=200 as sole signal is too generic"
	}

	if fp.Pattern == "" && fp.HttpStatus == 0 && len(fp.CNames) == 0 {
		switch {
		case hasRegexMatcher:
			return nil, "regex-only matcher (unsupported by Fingerprint.Pattern substring match)"
		case sawWordMatcher && headerOnlyWord:
			return nil, "only header-targeted word matchers (unsupported)"
		default:
			return nil, "no usable signal (no word/status/cname extracted)"
		}
	}
	return fp, ""
}

func normalizeName(s string) string {
	s = strings.TrimSpace(s)
	s = nameSuffixRE.ReplaceAllString(s, "")
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
