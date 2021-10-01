package checks

type IssueType string

const (
	IssueTargetNoResolve IssueType = "target might be unclaimed"
	IssueCnameTakeover             = "points to unclaimed resource"
	IssueNsTakeover                = "unclaimed zone delegation"
)

type DetectionMethod string

const (
	MethodCnameOnly    DetectionMethod = "CNAME only"
	MethodPatternOnly                  = "response body only"
	MethodCnamePattern                 = "CNAME + response body"
	MethodCnameLookup                  = "CNAME target lookup"
	MethodServfail                     = "SERVFAIL check"
)

type Finding struct {
	Domain  string
	Target  string
	Service string
	Type    IssueType
	Method  DetectionMethod
}
