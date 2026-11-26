package code

import (
	"regexp"
	"strings"
)

// A workflow's run: script is read just far enough to find the commands
// that deploy and the names they are given. It is not a shell: words are
// split the way a shell splits them, variables are replaced only by values
// the workflow file itself states, and everything else a shell would work
// out when it runs (command substitution, arithmetic, globbing) is left as
// "not known from the file". The script text is never stored.

// Markers wrap the name of something a value depends on and that the file
// does not settle: "\x01vars.ECS_SERVICE\x02". They travel inside resolved
// strings, so that "prod/\x01vars.SERVICE\x02" is known to be undetermined
// in its second part only.
const (
	markOpen  = "\x01"
	markClose = "\x02"
)

// Pseudo-names of what a value can depend on besides an expression.
const (
	unknownCommand    = "$(...)"                 // the output of a command
	unknownExpression = "expression"             // an expression that is not one name
	unknownStdin      = "stdin"                  // manifests piped in
	unknownWrangler   = "wrangler configuration" // a Worker's name that no wrangler file states
)

func mark(name string) string { return markOpen + name + markClose }

// shPart is a piece of a word and how it was quoted: not (0), in double
// quotes or in single quotes.
type shPart struct {
	text  string
	quote byte
}

type shWord []shPart

// lexScript splits a script into simple commands, each a list of words.
// Pipelines, lists and groups are flattened: every command in them is
// returned. subs holds the scripts inside $( ) and backquotes.
func lexScript(s string) (cmds [][]shWord, subs []string) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\\\n", " ")
	var cmd []shWord
	var word shWord
	var buf strings.Builder
	inWord := false
	skipNext := false // the next word is the target of a redirection
	flushPart := func(q byte) {
		if buf.Len() > 0 || q != 0 {
			word = append(word, shPart{buf.String(), q})
			buf.Reset()
		}
	}
	endWord := func() {
		flushPart(0)
		if inWord || len(word) > 0 {
			if skipNext {
				skipNext = false
			} else {
				cmd = append(cmd, word)
			}
		}
		word, inWord = nil, false
	}
	endCmd := func() {
		endWord()
		skipNext = false
		if len(cmd) > 0 {
			cmds = append(cmds, cmd)
		}
		cmd = nil
	}
	// balanced returns the index after the bracket that closes the one
	// opened before s[i:].
	balanced := func(i int, open, close byte) int {
		depth := 1
		for ; i < len(s); i++ {
			switch s[i] {
			case '\\':
				i++
			case open:
				depth++
			case close:
				depth--
				if depth == 0 {
					return i + 1
				}
			}
		}
		return len(s)
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == markOpen[0]:
			// A marker is copied whole: its name may hold "$" or "(".
			end := strings.IndexByte(s[i:], markClose[0])
			if end < 0 {
				end = len(s) - i - 1
			}
			buf.WriteString(s[i : i+end+1])
			inWord = true
			i += end + 1
		case c == '\'':
			flushPart(0)
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				end = len(s) - i - 1
			}
			word = append(word, shPart{s[i+1 : i+1+end], '\''})
			inWord = true
			i += end + 2
		case c == '"':
			flushPart(0)
			i++
			for i < len(s) && s[i] != '"' {
				switch {
				case s[i] == '\\' && i+1 < len(s) && strings.IndexByte("\"\\$`", s[i+1]) >= 0:
					if s[i+1] == '$' {
						buf.WriteString("\\$") // kept escaped: not a variable
					} else {
						buf.WriteByte(s[i+1])
					}
					i += 2
				case s[i] == '$' && i+1 < len(s) && s[i+1] == '(':
					end := balanced(i+2, '(', ')')
					subs = append(subs, s[i+2:max(i+2, end-1)])
					buf.WriteString(mark(unknownCommand))
					i = end
				case s[i] == '`':
					end := strings.IndexByte(s[i+1:], '`')
					if end < 0 {
						end = len(s) - i - 1
					}
					subs = append(subs, s[i+1:i+1+end])
					buf.WriteString(mark(unknownCommand))
					i += end + 2
				default:
					buf.WriteByte(s[i])
					i++
				}
			}
			flushPart('"')
			inWord = true
			i++
		case c == '\\' && i+1 < len(s):
			if s[i+1] == '$' {
				buf.WriteString("\\$")
			} else {
				buf.WriteByte(s[i+1])
			}
			inWord = true
			i += 2
		case c == '$' && i+1 < len(s) && s[i+1] == '(':
			end := balanced(i+2, '(', ')')
			subs = append(subs, s[i+2:max(i+2, end-1)])
			buf.WriteString(mark(unknownCommand))
			inWord = true
			i = end
		case c == '$' && i+1 < len(s) && s[i+1] == '{':
			end := balanced(i+2, '{', '}')
			buf.WriteString(s[i:end])
			inWord = true
			i = end
		case c == '`':
			end := strings.IndexByte(s[i+1:], '`')
			if end < 0 {
				end = len(s) - i - 1
			}
			subs = append(subs, s[i+1:i+1+end])
			buf.WriteString(mark(unknownCommand))
			inWord = true
			i += end + 2
		case c == ' ' || c == '\t':
			endWord()
			i++
		case c == '#' && !inWord && buf.Len() == 0:
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '>' || c == '<':
			// "2>" and "&>": the descriptor is not a word.
			if t := buf.String(); len(word) == 0 && (t == "&" || isDigits(t)) {
				buf.Reset()
				inWord = false
			}
			endWord()
			for i < len(s) && (s[i] == '>' || s[i] == '<' || s[i] == '&') {
				i++
			}
			skipNext = true
		case c == '\n' || c == ';' || c == '|' || c == '(' || c == ')':
			endCmd()
			i++
		case c == '&':
			// "&>" is a redirection; "&" and "&&" end the command.
			if i+1 < len(s) && s[i+1] == '>' {
				buf.WriteByte(c)
				i++
				continue
			}
			endCmd()
			i++
		default:
			buf.WriteByte(c)
			inWord = true
			i++
		}
	}
	endCmd()
	return cmds, subs
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

var shellVar = regexp.MustCompile(`\\\$|\$\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// expandWord replaces $NAME and ${NAME} outside single quotes with what
// lookup returns; a name lookup does not know becomes a marker.
func expandWord(w shWord, lookup func(name string) (string, bool)) string {
	var b strings.Builder
	for _, p := range w {
		if p.quote == '\'' {
			b.WriteString(p.text)
			continue
		}
		b.WriteString(shellVar.ReplaceAllStringFunc(p.text, func(m string) string {
			if m == `\$` {
				return "$"
			}
			sub := shellVar.FindStringSubmatch(m)
			name := sub[1] + sub[2]
			if v, ok := lookup(name); ok {
				return v
			}
			return mark("$" + name)
		}))
	}
	return b.String()
}

// shellKeywords can stand before a command without being one.
var shellKeywords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "do": true, "while": true, "until": true,
	"!": true, "{": true, "time": true, "sudo": true, "exec": true, "command": true, "nohup": true,
}

var assignment = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

// args is a command line after its command words, split into flags and
// positional arguments.
type args struct {
	flags map[string][]string // "--cluster" -> values; a flag without a value has an empty one
	pos   []string
}

func (a args) flag(names ...string) string {
	for _, n := range names {
		if vs := a.flags[n]; len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

func (a args) all(names ...string) []string {
	var out []string
	for _, n := range names {
		out = append(out, a.flags[n]...)
	}
	return out
}

func (a args) has(names ...string) bool {
	for _, n := range names {
		if _, ok := a.flags[n]; ok {
			return true
		}
	}
	return false
}

// parseArgs splits words into flags and positionals. A flag takes the next
// word as its value unless it is written "--flag=value", is listed in
// noValue, or the next word is itself a flag.
func parseArgs(words []string, noValue map[string]bool) args {
	a := args{flags: map[string][]string{}}
	for i := 0; i < len(words); i++ {
		w := words[i]
		switch {
		case w == "--":
			a.pos = append(a.pos, words[i+1:]...)
			return a
		case len(w) > 1 && w[0] == '-' && w != "-":
			if name, value, ok := strings.Cut(w, "="); ok {
				a.flags[name] = append(a.flags[name], value)
				continue
			}
			if !noValue[w] && i+1 < len(words) && (!strings.HasPrefix(words[i+1], "-") || words[i+1] == "-") {
				a.flags[w] = append(a.flags[w], words[i+1])
				i++
				continue
			}
			a.flags[w] = append(a.flags[w], "")
		default:
			a.pos = append(a.pos, w)
		}
	}
	return a
}
