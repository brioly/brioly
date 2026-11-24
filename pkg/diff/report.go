package diff

import (
	"fmt"
	"sort"
	"strings"
)

// Format renders a result as Markdown. Info events (detail changes) are
// only counted unless verbose is set.
func Format(r Result, verbose bool) string {
	if r.Rebaselined {
		return "The two snapshots were classified differently (schema, kind registry or label allowlist changed), so they cannot be compared. The newer one is the new baseline.\n"
	}
	counts := r.Counts()
	if len(r.Events) == 0 {
		return "No changes.\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d high, %d medium, %d low, %d info\n", counts[High], counts[Medium], counts[Low], counts[Info])
	for _, sev := range []string{High, Medium, Low, Info} {
		if counts[sev] == 0 || (sev == Info && !verbose) {
			continue
		}
		fmt.Fprintf(&b, "\n## %s\n\n", strings.ToUpper(sev[:1])+sev[1:])
		for _, e := range r.Events {
			if e.Severity != sev {
				continue
			}
			fmt.Fprintf(&b, "- **%s** %s `%s`", strings.ReplaceAll(e.Type, "_", " "), e.Kind, orSubject(e))
			if e.RuleID != "" {
				fmt.Fprintf(&b, " (%s)", e.RuleID)
			}
			b.WriteString("\n")
			if e.Type == EdgeAdded || e.Type == EdgeRemoved {
				continue
			}
			for _, c := range e.Changes {
				fmt.Fprintf(&b, "  - %s: `%s` → `%s`\n", c.Attribute, show(c.Before), show(c.After))
			}
		}
	}
	if counts[Info] > 0 && !verbose {
		b.WriteString("\nInfo events are detail changes (versions, sizes, tags); pass -v to list them.\n")
	}
	return b.String()
}

func orSubject(e Event) string {
	if e.Name != "" {
		return e.Name
	}
	return e.Subject
}

func show(v any) string {
	if v == nil {
		return "—"
	}
	s := fmt.Sprint(v)
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}

// Churn counts how often each attribute changed across a series of
// comparisons. It is the evidence for moving an attribute between tiers.
type Churn struct {
	Steps      int
	Rebaseline int
	// Structural and Detail map "kind.attribute" to a change count.
	Structural map[string]int
	Detail     map[string]int
	// BySeverity counts events per severity over all steps.
	BySeverity map[string]int
}

// Add records one comparison.
func (c *Churn) Add(r Result) {
	if c.Structural == nil {
		c.Structural, c.Detail, c.BySeverity = map[string]int{}, map[string]int{}, map[string]int{}
	}
	c.Steps++
	if r.Rebaselined {
		c.Rebaseline++
		return
	}
	for _, e := range r.Events {
		c.BySeverity[e.Severity]++
		target := c.Structural
		switch e.Type {
		case DetailChanged:
			target = c.Detail
		case StructuralChanged:
		default:
			continue
		}
		for _, ch := range e.Changes {
			target[e.Kind+"."+ch.Attribute]++
		}
	}
}

// Format renders the churn table, most frequent first.
func (c Churn) Format() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d comparisons (%d rebaselined): %d high, %d medium, %d low, %d info events\n",
		c.Steps, c.Rebaseline, c.BySeverity[High], c.BySeverity[Medium], c.BySeverity[Low], c.BySeverity[Info])
	for _, part := range []struct {
		title string
		m     map[string]int
	}{{"Structural attributes that changed", c.Structural}, {"Detail attributes that changed", c.Detail}} {
		if len(part.m) == 0 {
			continue
		}
		keys := make([]string, 0, len(part.m))
		for k := range part.m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if part.m[keys[i]] != part.m[keys[j]] {
				return part.m[keys[i]] > part.m[keys[j]]
			}
			return keys[i] < keys[j]
		})
		fmt.Fprintf(&b, "\n%s (changes / comparisons):\n", part.title)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %4d / %d  %s\n", part.m[k], c.Steps-c.Rebaseline, k)
		}
	}
	return b.String()
}
