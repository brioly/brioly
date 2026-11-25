package render

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/brioly/brioly/pkg/facts"
)

// Unverified replaces a citation of a fact ID that does not exist.
const Unverified = "⚠️ *(unverified)*"

var citation = regexp.MustCompile(`\[\[([^\[\]]+)\]\]`)

// Document is a model-written document to resolve.
type Document struct {
	Path     string // relative to the output directory
	Markdown string
	// Published documents (job descriptions) are read outside the company:
	// their source list is marked as internal.
	Published bool
}

// ResolveCitations turns [[id]] markers (fact, component or note IDs) into
// Markdown footnotes that point to each source. Citations of unknown IDs
// are replaced with an "unverified" marker. It returns the resolved text
// and the number of unknown citations.
func ResolveCitations(md string, s *facts.Snapshot, published bool) (string, int) {
	// Footnotes quote names and references: they are written from the
	// escaped copy, like every other document.
	if text, err := escaped(s); err == nil {
		s = text
	}
	g := newGraph(s)
	notes := map[string]facts.Annotation{}
	for _, a := range s.Annotations {
		notes[a.ID] = a
	}
	source := func(id string) (string, bool) {
		if f, ok := g.byID[id]; ok {
			return fmt.Sprintf("%s **%s** — %s", f.Kind, mdEscape(displayName(f)), evidence(f)), true
		}
		if c, ok := s.ComponentByID(id); ok {
			return fmt.Sprintf("Component **%s** (%s), identified by %s", mdEscape(c.Name), c.Role, evidence(g.byID[c.Anchor])), true
		}
		if a, ok := notes[strings.TrimPrefix(id, "note:")]; ok {
			by := ""
			if a.Author != "" {
				by = " by " + a.Author
			}
			return fmt.Sprintf("Team note%s: \"%s\"", by, mdEscape(a.Body)), true
		}
		return "", false
	}

	// A footnote's label comes from the ID it cites, not from its position:
	// numbered labels would shift through the whole document whenever one
	// citation is added, and bury the real change in the diff. Markdown
	// viewers show footnotes as numbers either way.
	labels := map[string]string{}
	var order, footnotes []string
	unknown := 0
	body := citation.ReplaceAllStringFunc(md, func(m string) string {
		id := strings.TrimSpace(citation.FindStringSubmatch(m)[1])
		l, seen := labels[id]
		if !seen {
			text, ok := source(id)
			if !ok {
				unknown++
				return Unverified
			}
			l = footnoteLabel(id)
			labels[id] = l
			order = append(order, l)
			footnotes = append(footnotes, text)
		}
		return "[^" + l + "]"
	})
	if len(footnotes) == 0 {
		return body, unknown
	}
	var b strings.Builder
	b.WriteString(strings.TrimRight(body, "\n"))
	if published {
		b.WriteString("\n\n---\n\n**Sources (internal — remove before publishing)**\n\n")
	} else {
		b.WriteString("\n\n---\n\n")
	}
	// Sorted by label, so a new source adds one line and moves none.
	idx := make([]int, len(order))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, c int) bool { return order[idx[a]] < order[idx[c]] })
	for _, i := range idx {
		fmt.Fprintf(&b, "[^%s]: %s\n", order[i], footnotes[i])
	}
	return b.String(), unknown
}

// footnoteLabel is a short, stable label for a cited ID.
func footnoteLabel(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])[:6]
}

// Written returns a model-written document as it is published: its
// citations resolved against s, under a line that says who wrote it. The
// second result is the number of citations that name nothing in s.
func Written(s *facts.Snapshot, d Document, producer string) (string, int) {
	text, unknown := ResolveCitations(d.Markdown, s, d.Published)
	header := fmt.Sprintf("> Written by %s from collected facts. Each statement cites its source; inferences are marked as such.", producer)
	if unknown > 0 {
		header += fmt.Sprintf(" %d statement(s) cite sources that do not exist and are marked unverified.", unknown)
	}
	return header + "\n\n" + strings.TrimSpace(text) + "\n", unknown
}

var nonSlug = regexp.MustCompile(`[^\p{L}\p{N}]+`)

// Slug turns a role title into a file name. Letters and digits of every
// script are kept, so "백엔드 엔지니어" and "프론트엔드 엔지니어" stay
// distinct.
func Slug(s string) string {
	slug := strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if slug == "" {
		return "role"
	}
	return slug
}

// UniquePath returns name with a numeric suffix if it is already in used,
// and records the result.
func UniquePath(used map[string]bool, dir, name, ext string) string {
	p := dir + name + ext
	for i := 2; used[p]; i++ {
		p = fmt.Sprintf("%s%s-%d%s", dir, name, i, ext)
	}
	used[p] = true
	return p
}
