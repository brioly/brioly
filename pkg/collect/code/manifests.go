package code

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"github.com/brioly/brioly/pkg/facts"
)

// frameworks maps a dependency (ecosystem:name) to the framework it reveals.
var frameworks = map[string]string{
	"npm:next": "Next.js", "npm:react": "React", "npm:vue": "Vue", "npm:nuxt": "Nuxt",
	"npm:express": "Express", "npm:@nestjs/core": "NestJS", "npm:fastify": "Fastify",
	"npm:svelte": "Svelte", "npm:@angular/core": "Angular", "npm:hono": "Hono",
	"npm:prisma": "Prisma", "npm:@prisma/client": "Prisma",
	"go:github.com/gin-gonic/gin": "Gin", "go:github.com/labstack/echo/v4": "Echo",
	"go:github.com/gofiber/fiber/v2": "Fiber", "go:github.com/go-chi/chi/v5": "chi",
	"go:google.golang.org/grpc": "gRPC", "go:gorm.io/gorm": "GORM",
	"pip:django": "Django", "pip:fastapi": "FastAPI", "pip:flask": "Flask",
	"pip:celery": "Celery", "pip:sqlalchemy": "SQLAlchemy",
}

// addDependency records a declared dependency and, when it reveals a
// framework, the framework.
func (r *repo) addDependency(rel, ecosystem, name, constraint string, dev bool, line int) {
	ref := r.fileRef(rel, line, line)
	f := facts.NewObserved(facts.DependencyID(r.id, rel, ecosystem, name), "code.dependency", name, r.src, ref, r.now)
	f.Attributes["ecosystem"] = ecosystem
	f.Attributes["version_constraint"] = constraint
	f.Attributes["major"] = facts.MajorVersion(constraint)
	f.Attributes["dev"] = dev
	f.Attributes["manifest"] = rel
	r.addFact(f, facts.EdgeUses)

	if fw, ok := frameworks[ecosystem+":"+name]; ok && !dev && !r.frameworks[fw] {
		if r.frameworks == nil {
			r.frameworks = map[string]bool{}
		}
		r.frameworks[fw] = true
		ff := facts.NewObserved(r.id+":framework:"+strings.ToLower(fw), "code.framework", fw, r.src, ref, r.now)
		ff.Attributes["detected_from"] = ecosystem + ":" + name
		r.addFact(ff, facts.EdgeUses)
	}
}

func (r *repo) parsePackageJSON(rel, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	for _, name := range sortedKeys(pkg.Dependencies) {
		r.addDependency(rel, "npm", name, pkg.Dependencies[name], false, lineOf(lines, `"`+name+`"`))
	}
	for _, name := range sortedKeys(pkg.DevDependencies) {
		r.addDependency(rel, "npm", name, pkg.DevDependencies[name], true, lineOf(lines, `"`+name+`"`))
	}
	return nil
}

func (r *repo) parseGoMod(rel, path string) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	inBlock := false
	for i, line := range lines {
		t := strings.TrimSpace(line)
		switch {
		case t == "require (":
			inBlock = true
			continue
		case inBlock && t == ")":
			inBlock = false
			continue
		case strings.HasPrefix(t, "require ") && !strings.HasSuffix(t, "("):
			t = strings.TrimSpace(strings.TrimPrefix(t, "require "))
		case !inBlock:
			continue
		}
		if strings.Contains(t, "// indirect") || t == "" || strings.HasPrefix(t, "//") {
			continue
		}
		fields := strings.Fields(t)
		if len(fields) >= 2 {
			r.addDependency(rel, "go", fields[0], fields[1], false, i+1)
		}
	}
	return nil
}

var requirementLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$`)

func (r *repo) parseRequirements(rel, path string) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if j := strings.Index(t, " #"); j >= 0 {
			t = strings.TrimSpace(t[:j])
		}
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "-") || strings.Contains(t, "://") {
			continue
		}
		m := requirementLine.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		constraint := strings.TrimSpace(strings.SplitN(m[3], ";", 2)[0])
		r.addDependency(rel, "pip", strings.ToLower(m[1]), constraint, false, i+1)
	}
	return nil
}

// lineOf returns the 1-based number of the first line containing needle, or 0.
func lineOf(lines []string, needle string) int {
	for i, l := range lines {
		if strings.Contains(l, needle) {
			return i + 1
		}
	}
	return 0
}
