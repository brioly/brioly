package render

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"

	"github.com/brioly/brioly/pkg/facts"
)

// toHTML turns a document into HTML the way a permissive viewer would:
// GitHub-flavored Markdown with raw HTML let through. What survives here
// is what a reader's browser would be handed.
func toHTML(t *testing.T, md string) string {
	t.Helper()
	var out bytes.Buffer
	gm := goldmark.New(goldmark.WithExtensions(extension.GFM), goldmark.WithRendererOptions(html.WithUnsafe()))
	if err := gm.Convert([]byte(md), &out); err != nil {
		t.Fatal(err)
	}
	// The empty comments Escape splits addresses with show nothing.
	return strings.ReplaceAll(out.String(), split, "")
}

func TestEscapeShowsTheValueAndNothingElse(t *testing.T) {
	for _, v := range []string{
		"[click](http://evil.example/x)",
		"![x](http://evil.example/p.png)",
		"see https://evil.example/login and www.evil.example now",
		"WWW.evil.example and admin@evil.example",
		"- looks like a list item",
		"+ another",
		"1. numbered",
		"12) numbered too",
		"ends with hashes ###",
		"a literal <!-- --> comment and https://x.example/<!-- -->",
		"     five leading spaces",
		"<img src=http://evil.example/p.png onerror=alert(1)>",
		"<script>alert(1)</script>",
		"**bold** and _emph_ and ~~gone~~",
		"`code` and ``more``",
		"a | b | c",
		"# not a heading",
		"> not a quote",
		"line one\n\n# heading on line three\n- item",
		"&lt;b&gt; &#60;i&#62; A & B",
		`back\slash and \[escaped\]`,
		"snake_case_name and _leading and trailing_",
		"app/[slug]/page.tsx",
		"arn:aws:iam::111122223333:role/*",
	} {
		got := toHTML(t, "Value: "+Escape(v)+" end\n")
		if strings.Count(got, "<") != 2 || !strings.HasPrefix(got, "<p>") {
			t.Errorf("%q became markup: %s", v, got)
		}
		// Read back as text, the value is what went in (line breaks as spaces).
		text := strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&amp;", "&").Replace(strings.TrimSuffix(strings.TrimPrefix(got, "<p>Value: "), " end</p>\n"))
		want := strings.Join(strings.FieldsFunc(v, func(c rune) bool { return c == '\n' }), " ")
		if strings.Join(strings.Fields(text), " ") != strings.Join(strings.Fields(want), " ") {
			t.Errorf("%q reads back as %q", v, text)
		}
		if unescape(Escape(v)) != strings.TrimSpace(strings.ReplaceAll(v, "\n", " ")) {
			t.Errorf("unescape(Escape(%q)) = %q", v, unescape(Escape(v)))
		}
	}
	// Right after a list marker, where a value often sits, it stays one item
	// of text: no nested list, no code block.
	for _, v := range []string{"- x", "+ x", "1. x", "     indented", "# x", "> x"} {
		got := toHTML(t, "- "+Escape(v)+"\n")
		if strings.Count(got, "<li>") != 1 || strings.Contains(got, "<pre>") || strings.Contains(got, "<h1") || strings.Contains(got, "<blockquote") {
			t.Errorf("%q after a list marker: %s", v, got)
		}
	}
	// What needs nothing is left alone: no noise in existing documents.
	for _, v := range []string{"shop-api", "my_service_name", "10.0.0.0/16", "registry.example/shop:1.2", "A & B", "eu-west-1a (primary)", "arn:aws:s3:::bucket/key", "awww.example", "^15.0.0", "node:22-alpine", "repo@sha256:abc", "v1.2.3-rc.1", "a-b", "x (y)"} {
		if Escape(v) != v {
			t.Errorf("Escape(%q) = %q", v, Escape(v))
		}
	}
}

// An empty value is not written as an empty code span: its two backticks
// would pair with backticks later on the line and let that text out.
func TestEmptyCodeSpanCannotPairWithALaterOne(t *testing.T) {
	later := Escape("``x`` [click](http://evil.example/k) ``")
	got := toHTML(t, "- API server "+code("")+" — "+code(later)+"\n")
	if strings.Contains(got, "<a ") || strings.Count(got, "<code>") != 1 {
		t.Errorf("an empty value let the next one out of its code span: %s", got)
	}
	// Nor does a value with a backtick end a span written around two values.
	got = toHTML(t, "- Ingress "+code(Escape("x`y")+"/"+Escape("name"))+" — "+code(Escape("[click](http://evil.example/i)"))+"\n")
	if strings.Contains(got, "<a ") || strings.Count(got, "<code>") != 2 {
		t.Errorf("a backtick in a value let the next one out: %s", got)
	}
}

func TestCodeShowsExactlyTheValue(t *testing.T) {
	for _, v := range []string{"app/[slug]/page.tsx", "a`b", "``", "x ``` y", "plain", "*_<>", "https://example.com/x"} {
		got := toHTML(t, "See "+code(Escape(v))+".\n")
		want := "<code>" + strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(v) + "</code>"
		if !strings.Contains(got, want) || strings.Count(got, "<code>") != 1 {
			t.Errorf("code(%q) rendered as %s, want %s", v, got, want)
		}
	}
}

const hostile = "x\n\n# Sign in again\n\n> banner\n\n[click](http://evil.example/x) ![pix](http://evil.example/p.png) admin@evil.example WWW.evil.example " +
	"%%{init: {'themeCSS':'.node rect{display:none}'}}%% $$x$$ " +
	"<img src=http://evil.example/q.png> <script>alert(1)</script> `tick` | cell | **b** \"quote\"\n```\nclick A href \"http://evil.example\"\n"

// benign has the shape of the hostile text for the renderer's own logic (a
// suffix on every value) and nothing a viewer would act on.
const benign = "x benign suffix evil.example"

// poison appends text to every value the documents can show.
func poison(s *facts.Snapshot, hostile string) {
	var walk func(v any) any
	walk = func(v any) any {
		switch t := v.(type) {
		case string:
			return t + hostile
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
			return t
		case []string:
			for i := range t {
				t[i] += hostile
			}
			return t
		case map[string]any:
			out := map[string]any{}
			for k, inner := range t {
				out[k+hostile] = walk(inner)
			}
			return out
		default:
			return v
		}
	}
	for i := range s.Facts {
		f := &s.Facts[i]
		f.Name += hostile
		f.Ref.Value += hostile
		f.Source.Scope += hostile
		for _, m := range []map[string]any{f.Attributes, f.Details, f.Volatile} {
			for k, v := range m {
				m[k] = walk(v)
			}
		}
		for k, v := range f.Labels {
			f.Labels[k+hostile] = v + hostile
		}
	}
	for i := range s.Coverage {
		s.Coverage[i].Status = facts.CoverageError
		s.Coverage[i].Detail += hostile
		s.Coverage[i].Scope += hostile
	}
	for i := range s.Components {
		s.Components[i].Name += hostile
		s.Components[i].Owner += hostile
	}
	for i := range s.Annotations {
		s.Annotations[i].Body += hostile
		s.Annotations[i].Author += hostile
		s.Annotations[i].TargetName += hostile
	}
}

// Whatever a collected value contains, the documents show it as text: no
// link, image, element, heading or quote of its making reaches the reader,
// and it cannot add a line to the diagram.
func TestHostileValuesStayText(t *testing.T) {
	for name, build := range map[string]func(*testing.T) *facts.Snapshot{"aws": testSnapshot} {
		s := build(t)
		s.Coverage = append(s.Coverage, facts.Coverage{Connector: "aws", Scope: "111122223333", Region: "eu-west-1", Kind: "aws.ec2.vpc", Status: facts.CoverageError})
		plain := build(t)
		plain.Coverage = append(plain.Coverage, s.Coverage[len(s.Coverage)-1])
		var out [2]map[string][]byte
		for n, snap := range []*facts.Snapshot{plain, s} {
			text := []string{benign, hostile}[n]
			// Two values that are not in the usual places: a coverage
			// kind, and a fact with no name, shown by the tail of its ID.
			nameless := "aws:111122223333:eu-west-1:ec2:vpc/[click](http&colon;&sol;&sol;evil.example&sol;id)"
			snap.Coverage = append(snap.Coverage, facts.Coverage{Connector: "aws", Scope: "111122223333", Kind: "x|[click](http://evil.example/c)", Status: facts.CoverageDenied})
			snap.Facts = append(snap.Facts, facts.Fact{ID: nameless, Kind: "aws.ec2.vpc",
				Attributes: map[string]any{"cidr_block": "10.9.0.0/16"}, Source: facts.Source{Connector: "aws", Scope: "111122223333", Region: "eu-west-1"}})
			poison(snap, text)
			snap.Facts[len(snap.Facts)-1].Name = ""
			files, err := Files(snap)
			if err != nil {
				t.Fatal(err)
			}
			out[n] = files
		}
		clean, files := out[0], out[1]
		// To check the same documents with another viewer (the tests here
		// use goldmark; brioly Cloud's viewer is remark), write them out:
		// BRIOLY_WRITE_HOSTILE=dir go test ./pkg/render -run Hostile
		if dir := os.Getenv("BRIOLY_WRITE_HOSTILE"); dir != "" {
			for _, f := range []string{ArchitectureFile, TechStackFile} {
				os.WriteFile(filepath.Join(dir, "hostile-"+f), files[f], 0o644)
				os.WriteFile(filepath.Join(dir, "benign-"+f), clean[f], 0o644)
			}
			os.WriteFile(filepath.Join(dir, "hostile.mmd"), files[DiagramFile], 0o644)
		}
		for _, file := range []string{ArchitectureFile, TechStackFile} {
			page := toHTML(t, string(files[file]))
			base := toHTML(t, string(clean[file]))
			for _, bad := range []string{"<img", "<script", ">click</a>", "<h1", "<blockquote>\n<p>banner", "<strong>b</strong>", "<del>"} {
				if strings.Count(page, bad) != strings.Count(base, bad) {
					t.Errorf("%s (%s): the hostile value produced %q", file, name, bad)
				}
			}
			// The same structure as without the hostile text: no table
			// gained a cell, no list an item, no section a heading.
			for _, tag := range []string{"<h2", "<h3", "<li>", "<td", "<tr>", "<table>", "<pre>"} {
				if a, b := strings.Count(page, tag), strings.Count(base, tag); a != b {
					t.Errorf("%s (%s): %d %s with hostile values, %d without", file, name, a, tag, b)
				}
			}
			if !strings.Contains(page, "evil.example") {
				t.Errorf("%s (%s): the hostile value was not rendered at all, so nothing was tested", file, name)
			}
		}
		for i, line := range strings.Split(string(files[DiagramFile]), "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "click ") || strings.HasPrefix(l, "```") || strings.Contains(l, "<img") || strings.Contains(l, "<script") {
				t.Errorf("diagram line %d was shaped by a value: %s", i+1, l)
			}
			if strings.Contains(l, "%%{") || strings.Contains(l, "$$") {
				t.Errorf("diagram line %d carries a directive or math from a value: %s", i+1, l)
			}
			if strings.Count(l, `"`)%2 != 0 {
				t.Errorf("diagram line %d has an unbalanced quote: %s", i+1, l)
			}
		}
		if got, want := strings.Count(string(files[DiagramFile]), "\n"), strings.Count(string(clean[DiagramFile]), "\n"); got != want {
			t.Errorf("the diagram has %d lines with hostile values, %d without", got, want)
		}
	}
}
