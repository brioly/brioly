package render

import (
	"reflect"
	"strings"
	"unicode"

	"github.com/brioly/brioly/pkg/facts"
)

// Everything a document says comes from collected values: resource names,
// tags, file paths, configuration. Those are text, never markup. A name is
// free to contain "[x](http://…)", "<img …>" or a line that starts with "#",
// and none of it may act as a link, an element or a heading in a document
// someone else reads.
//
// The documents are therefore written from a copy of the snapshot in which
// every such value is already escaped (escaped below), so no place that
// writes a value has to remember to. Two places need the value as it was:
// code spans, where a backslash is not an escape (code), and diagram
// labels, which have their own rules (label in diagram.go).

// split is put inside what a viewer would otherwise turn into a link by
// itself: a bare address ("https://…", "www.…") or an e-mail address. Those
// viewers look for such text after backslash escapes are resolved, so an
// escape does not stop them; an empty comment does, and shows nothing.
const split = "<!-- -->"

const escapable = "\\`*_[]<|~&#>-+.)"

// Escape returns s as Markdown that shows s and nothing else: characters
// that would start emphasis, a link, an image, HTML, a code span or a table
// cell are backslash-escaped, text a viewer would link by itself is split,
// and line breaks and control characters become spaces, so a value cannot
// begin a new block. An underscore inside a word is left alone, as Markdown
// does not treat it as emphasis and names are full of them.
func Escape(s string) string {
	// Spaces at the ends would start a code block at the head of a line and
	// keep "**value**" from being bold at its tail.
	s = strings.TrimSpace(s)
	if !strings.ContainsAny(s, "\\`*_[]<|~&#>@") && !strings.Contains(s, "://") &&
		!strings.Contains(strings.ToLower(s), "www.") && !strings.ContainsFunc(s, isBreak) && !startsBlock(s) {
		return s
	}
	rs := []rune(s)
	var b strings.Builder
	for i, c := range rs {
		switch {
		case isBreak(c):
			b.WriteRune(' ')
			continue
		case c == '\\' || c == '`' || c == '*' || c == '[' || c == ']' || c == '<' || c == '|' || c == '~':
			b.WriteRune('\\')
		case c == '_':
			inWord := i > 0 && i < len(rs)-1 && wordRune(rs[i-1]) && wordRune(rs[i+1])
			if !inWord {
				b.WriteRune('\\')
			}
		case c == '&':
			// Only where it would start a character reference.
			if i < len(rs)-1 && (rs[i+1] == '#' || unicode.IsLetter(rs[i+1])) {
				b.WriteRune('\\')
			}
		case c == '#' && (i == 0 || rs[i-1] == ' '):
			// A heading at the start of a line; at the end of one, the
			// closing marks of a heading, which would not be shown.
			b.WriteRune('\\')
		case i == 0 && (c == '>' || (c == '-' || c == '+') && (len(rs) == 1 || rs[1] == ' ')):
			// A quote or a list item, were the value to start a line.
			b.WriteRune('\\')
		case (c == '.' || c == ')') && i > 0 && i <= 9 && allDigits(rs[:i]) && (i == len(rs)-1 || rs[i+1] == ' '):
			// "1. " at the start of a line is a numbered list.
			b.WriteRune('\\')
		case c == ':' && i < len(rs)-2 && rs[i+1] == '/' && rs[i+2] == '/':
			b.WriteString(split)
		case c == '.' && i >= 3 && strings.EqualFold(string(rs[i-3:i]), "www") && (i == 3 || !wordRune(rs[i-4])):
			b.WriteString(split)
		case c == '@' && i > 0 && wordRune(rs[i-1]) && domainFollows(rs[i+1:]):
			b.WriteString(split)
		}
		b.WriteRune(c)
	}
	return b.String()
}

// startsBlock says whether s begins like a list item.
func startsBlock(s string) bool {
	if s == "" {
		return false
	}
	if (s[0] == '-' || s[0] == '+') && (len(s) == 1 || s[1] == ' ') {
		return true
	}
	i := 0
	for i < len(s) && i < 9 && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i > 0 && i < len(s) && (s[i] == '.' || s[i] == ')') && (i == len(s)-1 || s[i+1] == ' ')
}

// domainFollows says whether rs begins like the host of an e-mail address:
// name.name. An image digest ("repo@sha256:…") does not.
func domainFollows(rs []rune) bool {
	dot := false
	for i, c := range rs {
		switch {
		case wordRune(c) || c == '-' || c == '_':
		case c == '.' && i > 0 && i < len(rs)-1 && wordRune(rs[i+1]):
			dot = true
		default:
			return dot
		}
	}
	return dot
}

func allDigits(rs []rune) bool {
	for _, c := range rs {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(rs) > 0
}

func isBreak(c rune) bool {
	return unicode.IsControl(c) || c == '\u2028' || c == '\u2029'
}

func wordRune(c rune) bool { return unicode.IsLetter(c) || unicode.IsDigit(c) }

// unescape gives back the text Escape was given (line breaks stay spaces).
func unescape(s string) string {
	if !strings.Contains(s, `\`) && !strings.Contains(s, split) {
		return s
	}
	var b strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		switch {
		case rs[i] == '\\' && i < len(rs)-1 && strings.ContainsRune(escapable, rs[i+1]):
			// The escaped character itself, whatever it is: also the "<"
			// of a comment that was part of the value.
			i++
		case strings.HasPrefix(string(rs[i:min(i+len(split), len(rs))]), split):
			i += len(split) - 1
			continue
		}
		b.WriteRune(rs[i])
	}
	return b.String()
}

// code writes an escaped value as a code span that shows the value exactly
// (or, for a value with a pipe in it, as plain escaped text).
// Inside a code span a backslash is an ordinary character, so the value is
// unescaped first; the span is fenced with more backticks than the value
// has in a row, which is the one thing that could end it early.
func code(escaped string) string {
	s := unescape(escaped)
	// An empty code span cannot be written: two backticks alone would
	// pair with backticks further along the line.
	if strings.TrimSpace(s) == "" {
		return "(none)"
	}
	// In a table a pipe ends the cell even inside a code span, and a code
	// span cannot escape it. Such a value is shown as escaped text instead.
	if strings.Contains(s, "|") {
		return escaped
	}
	longest, run := 0, 0
	for _, c := range s {
		if c == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if longest > 0 || strings.HasPrefix(s, " ") && strings.HasSuffix(s, " ") {
		// A space keeps the value's own backticks apart from the fence.
		return fence + " " + s + " " + fence
	}
	return fence + s + fence
}

// escaped returns a copy of the snapshot for writing documents from: every
// value that can end up in a sentence, a heading or a table is run through
// Escape. Identifiers and kinds are left as they are (they are keys), as
// are the names of attributes; a fact without a name gets the escaped tail
// of its ID, which is what would be shown for it. The original is not
// changed, and numbers keep their types.
func escaped(s *facts.Snapshot) (*facts.Snapshot, error) {
	out := *s
	out.Facts = make([]facts.Fact, len(s.Facts))
	for i, f := range s.Facts {
		if f.Name == "" {
			f.Name = f.ID[strings.LastIndexAny(f.ID, "/:")+1:]
		}
		f.Name = Escape(f.Name)
		f.Source.Scope, f.Source.Region = Escape(f.Source.Scope), Escape(f.Source.Region)
		f.Ref.Value = Escape(f.Ref.Value)
		f.Attributes = escapeAttributes(f.Attributes)
		f.Details = escapeAttributes(f.Details)
		f.Volatile = escapeAttributes(f.Volatile)
		if f.Labels != nil {
			labels := make(map[string]string, len(f.Labels))
			for k, v := range f.Labels {
				labels[Escape(k)] = Escape(v)
			}
			f.Labels = labels
		}
		evidence := make([]string, len(f.Derivation.Evidence))
		for j, e := range f.Derivation.Evidence {
			evidence[j] = Escape(e)
		}
		f.Derivation.Evidence = evidence
		out.Facts[i] = f
	}
	out.Coverage = make([]facts.Coverage, len(s.Coverage))
	for i, c := range s.Coverage {
		c.Connector, c.Kind = Escape(c.Connector), Escape(c.Kind)
		c.Scope, c.Region, c.Detail = Escape(c.Scope), Escape(c.Region), Escape(c.Detail)
		out.Coverage[i] = c
	}
	out.Components = make([]facts.Component, len(s.Components))
	for i, c := range s.Components {
		c.Name, c.Owner = Escape(c.Name), Escape(c.Owner)
		out.Components[i] = c
	}
	out.Annotations = make([]facts.Annotation, len(s.Annotations))
	for i, a := range s.Annotations {
		a.Body, a.Author, a.TargetName = Escape(a.Body), Escape(a.Author), Escape(a.TargetName)
		out.Annotations[i] = a
	}
	return &out, nil
}

// escapeAttributes copies an attribute map with its strings escaped, at any
// depth. The map's own keys are attribute names and stay; keys further down
// (the names of tags, for example) are values someone chose and are escaped.
func escapeAttributes(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = escapeValue(reflect.ValueOf(v))
	}
	return out
}

// escapeValue copies v with every string in it escaped. Collectors put
// typed values into attributes ([]string, map[string]string, ints), and a
// stored snapshot holds the JSON shapes: both are handled, and everything
// that is not text is returned as it is.
func escapeValue(v reflect.Value) any {
	if !v.IsValid() {
		return nil
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return v.Interface()
		}
		return escapeValue(v.Elem())
	case reflect.String:
		return Escape(v.String())
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return v.Interface()
		}
		out := make([]any, v.Len())
		for i := range out {
			out[i] = escapeValue(v.Index(i))
		}
		return out
	case reflect.Map:
		if v.IsNil() || v.Type().Key().Kind() != reflect.String {
			return v.Interface()
		}
		out := make(map[string]any, v.Len())
		for _, k := range v.MapKeys() {
			out[Escape(k.String())] = escapeValue(v.MapIndex(k))
		}
		return out
	default:
		return v.Interface()
	}
}
