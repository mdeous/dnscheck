package checker

import (
	"encoding/json"
	"errors"
	"testing"
)

// A dangling record is only a takeover when an attacker can claim the target.
// Deciding it cannot be claimed takes positive evidence: these tests pin down
// that an inconclusive lookup keeps the takeover classification instead of
// quietly downgrading a real finding to a misconfiguration.

func TestNsIssueType(t *testing.T) {
	registered := nsStatus{name: "dns.google.", registered: true}
	unregistered := nsStatus{name: "ns1.gone.example.", unregistered: true}
	unknown := nsStatus{name: "ns1.unreachable.example.", inconclusive: true}

	tests := []struct {
		name     string
		statuses []nsStatus
		partial  bool
		want     IssueType
	}{
		{
			name:     "every nameserver unregistered is a takeover",
			statuses: []nsStatus{unregistered, unregistered},
			want:     IssueDanglingNs,
		},
		{
			name:     "one unregistered nameserver is a partial takeover",
			statuses: []nsStatus{registered, unregistered},
			partial:  true,
			want:     IssuePartialDanglingNs,
		},
		{
			name:     "every nameserver registered cannot be claimed",
			statuses: []nsStatus{registered, registered},
			want:     IssueDanglingUnclaimable,
		},
		{
			name:     "single registered nameserver cannot be claimed",
			statuses: []nsStatus{registered},
			want:     IssueDanglingUnclaimable,
		},
		{
			// the fail-open this guards: DomainIsNXDOMAIN returns false when
			// its query fails, so an unreachable nameserver must not be read
			// as proof that nothing is claimable
			name:     "inconclusive lookup stays a takeover",
			statuses: []nsStatus{unknown},
			want:     IssueDanglingNs,
		},
		{
			name:     "inconclusive alongside registered stays a takeover",
			statuses: []nsStatus{registered, unknown},
			want:     IssueDanglingNs,
		},
		{
			name:     "inconclusive stays a partial takeover when partial",
			statuses: []nsStatus{registered, unknown},
			partial:  true,
			want:     IssuePartialDanglingNs,
		},
		{
			name:     "no nameservers at all is not downgraded",
			statuses: nil,
			want:     IssueDanglingUnclaimable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nsIssueType(tt.statuses, tt.partial); got != tt.want {
				t.Errorf("nsIssueType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMxClassification(t *testing.T) {
	tests := []struct {
		name           string
		claimable      bool
		lookupErr      error
		wantIssue      IssueType
		wantConfidence ConfidenceLevel
		wantUnknown    bool
	}{
		{
			name:           "claimable domain is a takeover",
			claimable:      true,
			wantIssue:      IssueDanglingMx,
			wantConfidence: ConfidenceHigh,
		},
		{
			name:           "unclaimable domain is only a misconfiguration",
			claimable:      false,
			wantIssue:      IssueDanglingUnclaimable,
			wantConfidence: ConfidenceMedium,
		},
		{
			// the fail-open this guards: a failed availability check used to
			// land in the same branch as a confirmed-unclaimable domain
			name:           "failed lookup stays a takeover at low confidence",
			claimable:      false,
			lookupErr:      errors.New("no resolver could answer"),
			wantIssue:      IssueDanglingMx,
			wantConfidence: ConfidenceLow,
			wantUnknown:    true,
		},
		{
			name:           "failed lookup stays a takeover even if claimable was set",
			claimable:      true,
			lookupErr:      errors.New("no resolver could answer"),
			wantIssue:      IssueDanglingMx,
			wantConfidence: ConfidenceLow,
			wantUnknown:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issue, confidence, unknown := mxClassification(tt.claimable, tt.lookupErr)
			if issue != tt.wantIssue {
				t.Errorf("issue = %q, want %q", issue, tt.wantIssue)
			}
			if confidence != tt.wantConfidence {
				t.Errorf("confidence = %q, want %q", confidence, tt.wantConfidence)
			}
			if unknown != tt.wantUnknown {
				t.Errorf("claimability unknown = %v, want %v", unknown, tt.wantUnknown)
			}
		})
	}
}

func TestIssueTypeExploitable(t *testing.T) {
	exploitable := []IssueType{
		IssueDanglingCname,
		IssueDanglingNs,
		IssuePartialDanglingNs,
		IssueDanglingMx,
		IssueUnregistered,
		IssueUnregisteredNs,
	}
	for _, issue := range exploitable {
		if !issue.Exploitable() {
			t.Errorf("%q should be exploitable", issue)
		}
	}
	if IssueType(IssueDanglingUnclaimable).Exploitable() {
		t.Errorf("%q should not be exploitable", IssueDanglingUnclaimable)
	}
}

func TestMatchMarshalJSONCarriesExploitable(t *testing.T) {
	tests := []struct {
		issue IssueType
		want  bool
	}{
		{IssueDanglingCname, true},
		{IssueDanglingUnclaimable, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.issue), func(t *testing.T) {
			raw, err := json.Marshal(&Match{
				Domain: "sub.example.test",
				Target: "gone.example.test",
				Type:   tt.issue,
				Method: MethodNxdomain,
			})
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			var decoded struct {
				Type        string `json:"type"`
				Exploitable bool   `json:"exploitable"`
			}
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if decoded.Exploitable != tt.want {
				t.Errorf("exploitable = %v, want %v", decoded.Exploitable, tt.want)
			}
			if decoded.Type != string(tt.issue) {
				t.Errorf("type = %q, want %q", decoded.Type, tt.issue)
			}
		})
	}
}
