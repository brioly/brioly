package code

import (
	"path/filepath"
	"strings"
)

var extLanguages = map[string]string{
	".go": "Go", ".ts": "TypeScript", ".tsx": "TypeScript", ".js": "JavaScript", ".jsx": "JavaScript",
	".mjs": "JavaScript", ".cjs": "JavaScript", ".py": "Python", ".java": "Java", ".kt": "Kotlin",
	".kts": "Kotlin", ".scala": "Scala", ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".rs": "Rust",
	".swift": "Swift", ".dart": "Dart", ".ex": "Elixir", ".exs": "Elixir", ".c": "C", ".h": "C",
	".cpp": "C++", ".cc": "C++", ".hpp": "C++", ".vue": "Vue", ".svelte": "Svelte", ".tf": "HCL",
	".sql": "SQL", ".sh": "Shell", ".bash": "Shell",
}

// languageOf returns the language of a file, or "" for files that are not
// source code (docs, data, lock files, generated assets).
func languageOf(rel string) string {
	if strings.HasSuffix(rel, ".d.ts") || strings.HasSuffix(rel, ".min.js") {
		return ""
	}
	return extLanguages[strings.ToLower(filepath.Ext(rel))]
}

// languageShares turns byte counts into percentages rounded to 5% so that
// small edits do not change the repository fact's hash. Languages below
// 2.5% are dropped. It also returns the language with the most bytes.
func languageShares(bytes map[string]int64) (map[string]int, string) {
	var total int64
	primary, max := "", int64(-1)
	for _, lang := range sortedKeys(bytes) {
		b := bytes[lang]
		total += b
		if b > max {
			primary, max = lang, b
		}
	}
	out := map[string]int{}
	if total == 0 {
		return out, ""
	}
	for lang, b := range bytes {
		pct := float64(b) * 100 / float64(total)
		rounded := int((pct+2.5)/5) * 5
		if rounded > 0 {
			out[lang] = rounded
		}
	}
	return out, primary
}
