// Package lifecycle says when the versions a system runs on stop being
// supported: cluster versions, database engines, function runtimes, base
// images and a few frameworks.
//
// It looks versions up in a table of published dates. The table is not
// part of the program: brioly.io serves it (DefaultURL), and the CLI and
// brioly Cloud both read it from there, so that both always judge by the
// same dates and a new date does not wait for a release. The request sends
// nothing about the system being scanned. No model is involved: a version
// that is not in the table is reported as not known, never guessed.
package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/brioly/brioly/pkg/facts"
)

// DefaultURL is where the table is read from.
const DefaultURL = "https://brioly.io/lifecycle/v1/data.json"

// URLEnv names the environment variable that replaces DefaultURL: for a
// mirror inside a network that cannot reach brioly.io, and for tests.
const URLEnv = "BRIOLY_LIFECYCLE_URL"

// URL returns the address the table is read from.
func URL() string {
	if u := os.Getenv(URLEnv); u != "" {
		return u
	}
	return DefaultURL
}

// maxTableBytes bounds what is read from the address.
const maxTableBytes = 4 << 20

// Fetch reads the table from url. Any failure is an error that says what
// went wrong: there is no table inside the program to fall back on.
func Fetch(ctx context.Context, url string) (*Table, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("version support dates: %s is not an address: %w", url, err)
	}
	req.Header.Set("User-Agent", "brioly")
	req.Header.Set("Accept", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("version support dates: %s could not be reached: %w", url, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("version support dates: %s answered %s", url, res.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxTableBytes+1))
	if err != nil {
		return nil, fmt.Errorf("version support dates: reading %s: %w", url, err)
	}
	if len(raw) > maxTableBytes {
		return nil, fmt.Errorf("version support dates: %s is larger than %d bytes", url, maxTableBytes)
	}
	t, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("version support dates: %s: %w", url, err)
	}
	return t, nil
}

// Parse reads a table and checks it: what comes from an address is used
// only if it has the shape and the dates a table has.
func Parse(raw []byte) (*Table, error) {
	var t Table
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("not a table of dates: %w", err)
	}
	if _, err := time.Parse("2006-01-02", t.Updated); err != nil {
		return nil, errors.New("not a table of dates: no day it was updated")
	}
	if len(t.Products) == 0 {
		return nil, errors.New("not a table of dates: no products")
	}
	for id, p := range t.Products {
		if p.Name == "" || len(p.Cycles) == 0 {
			return nil, fmt.Errorf("not a table of dates: product %q has no name or no versions", id)
		}
		for _, c := range p.Cycles {
			if c.Cycle == "" {
				return nil, fmt.Errorf("not a table of dates: product %q has a version without a name", id)
			}
			for _, day := range []string{c.EOL, c.Extended} {
				if day == "" || day == "ended" {
					continue
				}
				if _, err := time.Parse("2006-01-02", day); err != nil {
					return nil, fmt.Errorf("not a table of dates: %q of %s %s is not a day", day, id, c.Cycle)
				}
			}
		}
	}
	return &t, nil
}

// Table is the end-of-support dates brioly knows.
type Table struct {
	// Updated is the day the table was last refreshed (YYYY-MM-DD).
	Updated  string             `json:"updated"`
	Source   string             `json:"source"`
	Products map[string]Product `json:"products"`
}

// Product is one thing with versions: a managed service, a language, an
// operating system.
type Product struct {
	Name   string  `json:"name"`
	Cycles []Cycle `json:"cycles"`
}

// Cycle is one supported line of a product, such as Kubernetes 1.30.
type Cycle struct {
	Cycle string `json:"cycle"`
	// EOL is the day standard support ends (YYYY-MM-DD), "ended" when it
	// has ended on a day the table does not give, or "" when no end is
	// announced.
	EOL string `json:"eol"`
	// Extended is the day paid or extended support ends, when there is one.
	Extended string `json:"extended"`
}

// States of an item, from the one that needs attention first.
const (
	Ended     = "ended"     // standard support is over
	EndsSoon  = "ends_soon" // it ends within Soon of the scan
	Supported = "supported"
	NoEndDate = "no_end_date" // the version is known, no end is announced
	Unknown   = "unknown"     // the product or the version is not in the table
)

// Soon is how far ahead an end of support counts as close.
const Soon = 183 * 24 * time.Hour

// Item is one versioned thing found in a snapshot.
type Item struct {
	// FactID is the fact the version was read from.
	FactID string
	// What says what kind of thing it is: "EKS cluster", "Base image".
	What string
	// Product is the name in the table, or "" when the product is not
	// one brioly has dates for.
	Product string
	// Version is the version as collected ("1.30", "python3.12",
	// "node:22-alpine").
	Version string
	// Cycle is the line of the product it was matched to, or "".
	Cycle    string
	EOL      string
	Extended string
	State    string
}

// Find returns the versioned things in s with what table says about them,
// as of at: the time of the scan, so that the same snapshot always
// gives the same answer. Items are ordered by how soon they need attention,
// then by what they are.
func Find(s *facts.Snapshot, at time.Time, table *Table) []Item {
	var items []Item
	add := func(f facts.Fact, what, product, version string, candidates ...string) {
		if version == "" {
			return
		}
		it := Item{FactID: f.ID, What: what, Version: version, State: Unknown}
		if p, ok := table.Products[product]; ok {
			it.Product = p.Name
			if c, ok := match(p, candidates); ok {
				it.Cycle, it.EOL, it.Extended = c.Cycle, c.EOL, c.Extended
				it.State = state(c.EOL, at)
			}
		}
		items = append(items, it)
	}
	for _, f := range s.Facts {
		attr := func(k string) string { v, _ := f.Attributes[k].(string); return v }
		detail := func(k string) string { v, _ := f.Details[k].(string); return v }
		switch f.Kind {
		case "aws.eks.cluster":
			add(f, "EKS cluster", "amazon-eks", attr("version"), attr("version"))
		case "k8s.cluster":
			if v := attr("version"); v != "" {
				add(f, "Kubernetes cluster", "kubernetes", v, strings.TrimPrefix(v, "v"), majorMinor(v))
			}
		case "aws.lambda.function":
			add(f, "Lambda function", "aws-lambda", attr("runtime"), attr("runtime"))
		case "aws.rds.cluster", "aws.rds.instance":
			if f.Kind == "aws.rds.instance" && f.Attributes["cluster_id"] != nil {
				continue // a member of a cluster: the cluster is listed
			}
			engine, major, full := attr("engine"), attr("engine_major"), detail("engine_version")
			what := "Database"
			switch {
			case engine == "aurora-postgresql":
				add(f, what, "amazon-aurora-postgresql", engine+" "+major, major)
			case engine == "aurora-mysql" || engine == "aurora":
				// Aurora MySQL has versions of its own: 8.0.mysql_aurora.3.05.2 is Aurora 3.
				add(f, what, "amazon-aurora-mysql", engine+" "+major, auroraMySQL(full))
			case engine == "postgres":
				add(f, what, "amazon-rds-postgresql", engine+" "+major, major)
			case engine == "mysql":
				add(f, what, "amazon-rds-mysql", engine+" "+major, full, major)
			case engine == "mariadb":
				add(f, what, "amazon-rds-mariadb", engine+" "+major, major)
			case engine != "":
				add(f, what, "", strings.TrimSpace(engine+" "+major))
			}
		case "aws.elasticache.cache":
			// Dates are known for ElastiCache's Redis OSS versions, by
			// major version; Valkey and Memcached are listed as not known.
			engine, major := attr("engine"), attr("engine_major")
			if major == "" {
				continue // the version could not be read
			}
			product := ""
			if engine == "redis" {
				product = "amazon-elasticache-redis"
			}
			add(f, "Cache", product, engine+" "+major, major)
		case "code.dockerfile":
			image := attr("final_base_image")
			if image == "" || image == "scratch" {
				continue
			}
			if strings.HasPrefix(image, "stage:") {
				continue
			}
			// The collector keeps the image without its tag and, apart,
			// the version the tag starts with.
			shown := image
			if v := detail("final_base_image_version"); v != "" {
				shown = image + ":" + v
			}
			product, version := baseImage(shown)
			add(f, "Base image", product, shown, version, majorMinor(version), major(version))
		case "code.dependency":
			if f.Attributes["dev"] == true {
				continue
			}
			product, ok := frameworks[attr("ecosystem")+":"+f.Name]
			if m := attr("major"); ok && m != "" {
				add(f, "Framework", product, f.Name+" "+m, m)
			}
		}
	}
	rank := map[string]int{Ended: 0, EndsSoon: 1, Supported: 2, NoEndDate: 3, Unknown: 4}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if rank[a.State] != rank[b.State] {
			return rank[a.State] < rank[b.State]
		}
		if a.EOL != b.EOL {
			return a.EOL < b.EOL
		}
		if a.What != b.What {
			return a.What < b.What
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.FactID < b.FactID
	})
	return items
}

// frameworks maps a dependency to its product, for the frameworks whose
// supported lines are whole major versions (the only part of a dependency's
// version brioly keeps as structural).
var frameworks = map[string]string{
	"npm:next": "nextjs", "npm:@angular/core": "angular", "npm:nuxt": "nuxt",
}

// images maps the name of an official image to its product.
var images = map[string]string{
	"node": "nodejs", "python": "python", "golang": "go", "ruby": "ruby", "php": "php",
	"eclipse-temurin": "eclipse-temurin", "nginx": "nginx", "alpine": "alpine-linux", "debian": "debian",
	"ubuntu": "ubuntu", "redis": "redis", "postgres": "postgresql", "mysql": "mysql",
}

var leadingVersion = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)`)

// baseImage returns the product of an image reference and the version its
// tag starts with: "public.ecr.aws/docker/library/node:22-alpine" is
// ("nodejs", "22"). An image that is not an official one of a product
// brioly knows, or has no version in its tag, gives "" for that part.
func baseImage(ref string) (product, version string) {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	name, tag := ref, ""
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		name, tag = ref[:i], ref[i+1:]
	}
	parts := strings.Split(name, "/")
	// Only official images: "node", "library/node", or a mirror of the
	// library. "acme/node" is somebody's own image.
	if len(parts) > 1 && parts[len(parts)-2] != "library" {
		return "", ""
	}
	product = images[parts[len(parts)-1]]
	if m := leadingVersion.FindStringSubmatch(tag); m != nil {
		version = m[1]
	}
	return product, version
}

var auroraVersion = regexp.MustCompile(`mysql_aurora\.(\d+)`)

func auroraMySQL(engineVersion string) string {
	if m := auroraVersion.FindStringSubmatch(engineVersion); m != nil {
		return m[1]
	}
	return ""
}

func major(v string) string {
	if m := leadingVersion.FindStringSubmatch(v); m != nil {
		return strings.SplitN(m[1], ".", 2)[0]
	}
	return ""
}

func majorMinor(v string) string {
	if m := leadingVersion.FindStringSubmatch(v); m != nil {
		if p := strings.Split(m[1], "."); len(p) >= 2 {
			return p[0] + "." + p[1]
		}
	}
	return ""
}

// match finds the line of p a version belongs to. The candidates are tried
// in order, exactly. Failing that, when every line that starts with a
// candidate (8.0.44, 8.0.45 for "8.0") ends on the same day, that is the
// answer; when they differ, there is none.
func match(p Product, candidates []string) (Cycle, bool) {
	for _, want := range candidates {
		if want == "" {
			continue
		}
		for _, c := range p.Cycles {
			if c.Cycle == want {
				return c, true
			}
		}
	}
	for _, want := range candidates {
		if want == "" {
			continue
		}
		var found *Cycle
		same := true
		for i, c := range p.Cycles {
			if !strings.HasPrefix(c.Cycle, want+".") {
				continue
			}
			if found == nil {
				found = &p.Cycles[i]
			} else if c.EOL != found.EOL || c.Extended != found.Extended {
				same = false
			}
		}
		if found != nil && same {
			return Cycle{Cycle: want, EOL: found.EOL, Extended: found.Extended}, true
		}
	}
	return Cycle{}, false
}

func state(eol string, at time.Time) string {
	switch eol {
	case "":
		return NoEndDate
	case "ended":
		return Ended
	}
	day, err := time.Parse("2006-01-02", eol)
	if err != nil {
		return Unknown
	}
	switch {
	case at.IsZero():
		return Supported // no time to compare with: the date is still shown
	case !day.After(at):
		return Ended
	case !day.After(at.Add(Soon)):
		return EndsSoon
	}
	return Supported
}
