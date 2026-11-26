// Package redact masks secrets in collected facts before they are stored or
// sent to an LLM. It is the second line of defence: collectors already only
// copy allow-listed attributes and never keep environment variable values.
package redact

import (
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/zricethezav/gitleaks/v8/detect"

	"github.com/brioly/brioly/pkg/facts"
)

// Placeholder replaces every detected secret.
const Placeholder = "[REDACTED]"

// sensitiveKeyParts mark map keys whose values are masked regardless of what
// the value looks like.
var sensitiveKeyParts = []string{"password", "passwd", "secret", "token", "apikey", "api_key", "private_key", "credential"}

// urlCredentials matches the user:password@ part of a URL, as in
// postgres://admin:pw@host or git::https://deploy:token@git.example.com.
// gitleaks has no rule for this shape, so it is masked here.
var urlCredentials = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@`)

// Redactor masks secrets using the gitleaks default rule set.
type Redactor struct {
	mu  sync.Mutex
	det *detect.Detector
}

// New returns a Redactor with the gitleaks default configuration.
func New() (*Redactor, error) {
	det, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, err
	}
	return &Redactor{det: det}, nil
}

var (
	sharedOnce sync.Once
	shared     *Redactor
	sharedErr  error
)

// Shared returns one Redactor for the process. Loading the rules takes a
// moment, and a collector that asks per repository would pay it each time.
func Shared() (*Redactor, error) {
	sharedOnce.Do(func() { shared, sharedErr = New() })
	return shared, sharedErr
}

// Masks reports whether value would be changed when stored as the value of
// attribute key ("" for a value with no key: a name, an ID). A collector
// asks before it builds an ID from a value: an ID is never masked
// afterwards, so it must not hold what would be.
func (r *Redactor) Masks(key, value string) bool {
	if key != "" && sensitiveKey(key) {
		return value != ""
	}
	_, changed := r.keyed(key, value)
	return changed
}

// String returns s with detected secrets replaced, and whether anything was
// replaced.
func (r *Redactor) String(s string) (string, bool) {
	return r.keyed("", s)
}

// keyed masks secrets in value. When key is set, gitleaks also sees
// "key=value": many of its rules (generic API keys, passwords) only match
// with that context, and a bare attribute or tag value has none.
func (r *Redactor) keyed(key, value string) (string, bool) {
	if strings.TrimSpace(value) == "" {
		return value, false
	}
	out := urlCredentials.ReplaceAllString(value, "${1}"+Placeholder+"@")

	inputs := []string{out}
	if key != "" {
		inputs = append(inputs, key+"="+out)
	}
	var secrets []string
	r.mu.Lock()
	for _, in := range inputs {
		for _, f := range r.det.DetectString(in) {
			secret := f.Secret
			if secret == "" {
				secret = f.Match
			}
			// A match on the key=value form may include the key; only
			// the part inside the value can be replaced.
			if secret != "" && strings.Contains(out, secret) {
				secrets = append(secrets, secret)
			}
		}
	}
	r.mu.Unlock()

	// Replace longer secrets first so a secret that contains another one is
	// masked as a whole.
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	for _, sec := range secrets {
		out = strings.ReplaceAll(out, sec, Placeholder)
	}
	return out, out != value
}

// Fact masks secrets in a fact's name, attributes, details, volatile
// values and labels. It returns the number of values that were changed.
func (r *Redactor) Fact(f *facts.Fact) int {
	n := 0
	if v, ok := r.String(f.Name); ok {
		f.Name, n = v, n+1
	}
	n += r.walkMap(f.Attributes)
	// Empty until Finalize sorts values into tiers; a snapshot that was
	// already finalized elsewhere has its detail values and other tags here.
	n += r.walkMap(f.Details)
	n += r.walkMap(f.Volatile)
	for k, v := range f.Labels {
		if sensitiveKey(k) {
			f.Labels[k] = Placeholder
			n++
			continue
		}
		if masked, ok := r.keyed(k, v); ok {
			f.Labels[k] = masked
			n++
		}
	}
	return n
}

// Snapshot masks every fact and every coverage detail (raw error text) in
// the snapshot and returns the total number of changed values.
func (r *Redactor) Snapshot(s *facts.Snapshot) int {
	n := 0
	for i := range s.Facts {
		n += r.Fact(&s.Facts[i])
	}
	for i := range s.Coverage {
		if masked, ok := r.String(s.Coverage[i].Detail); ok {
			s.Coverage[i].Detail = masked
			n++
		}
	}
	return n
}

func (r *Redactor) walkMap(m map[string]any) int {
	n := 0
	for k, v := range m {
		if sensitiveKey(k) {
			if s, ok := v.(string); ok && s != "" && s != Placeholder {
				m[k] = Placeholder
				n++
			}
			continue
		}
		if str, ok := v.(string); ok {
			if masked, changed := r.keyed(k, str); changed {
				m[k] = masked
				n++
			}
			continue
		}
		nv, c := r.walkValue(v)
		m[k] = nv
		n += c
	}
	return n
}

func (r *Redactor) walkValue(v any) (any, int) {
	switch t := v.(type) {
	case string:
		if masked, ok := r.String(t); ok {
			return masked, 1
		}
		return t, 0
	case []string:
		n := 0
		for i, s := range t {
			if masked, ok := r.String(s); ok {
				t[i] = masked
				n++
			}
		}
		return t, n
	case []any:
		n := 0
		for i, e := range t {
			nv, c := r.walkValue(e)
			t[i] = nv
			n += c
		}
		return t, n
	case map[string]any:
		return t, r.walkMap(t)
	case map[string]string:
		n := 0
		for k, s := range t {
			if sensitiveKey(k) {
				if s != Placeholder {
					t[k] = Placeholder
					n++
				}
				continue
			}
			if masked, ok := r.keyed(k, s); ok {
				t[k] = masked
				n++
			}
		}
		return t, n
	case []map[string]any:
		n := 0
		for _, m := range t {
			n += r.walkMap(m)
		}
		return t, n
	default:
		return v, 0
	}
}

func sensitiveKey(k string) bool {
	k = strings.ToLower(k)
	for _, p := range sensitiveKeyParts {
		if strings.Contains(k, p) {
			return true
		}
	}
	return false
}
