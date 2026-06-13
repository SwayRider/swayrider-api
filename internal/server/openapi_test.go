package server

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestOpenAPISpecCoversAllRoutes ensures every method+path registered in routes.go
// is documented in api/openapi.yaml. Bare-path patterns (e.g. /v1/tiles/ and /web/)
// that have no HTTP method prefix are excluded — they are catch-all proxy routes.
// When adding a new route to routes.go, add a corresponding entry to api/openapi.yaml.
func TestOpenAPISpecCoversAllRoutes(t *testing.T) {
	src, err := os.ReadFile("routes.go")
	if err != nil {
		t.Fatalf("reading routes.go: %v", err)
	}

	specBytes, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("reading api/openapi.yaml: %v", err)
	}

	var spec map[string]interface{}
	if err := yaml.Unmarshal(specBytes, &spec); err != nil {
		t.Fatalf("parsing openapi.yaml: %v", err)
	}

	rawPaths, ok := spec["paths"]
	if !ok {
		t.Fatal("openapi.yaml has no 'paths' key")
	}
	paths, ok := rawPaths.(map[string]interface{})
	if !ok {
		t.Fatal("openapi.yaml 'paths' is not a map")
	}

	re := regexp.MustCompile(`"((?:GET|POST|PUT|DELETE|PATCH) /[^"]+)"`)
	matches := re.FindAllSubmatch(src, -1)

	for _, match := range matches {
		pattern := string(match[1])
		parts := strings.SplitN(pattern, " ", 2)
		method := strings.ToLower(parts[0])
		path := parts[1]

		pathEntry, exists := paths[path]
		if !exists {
			t.Errorf("route %q: path not found in openapi.yaml", pattern)
			continue
		}

		methodMap, ok := pathEntry.(map[string]interface{})
		if !ok {
			t.Errorf("route %q: openapi.yaml path entry is not a map", pattern)
			continue
		}

		if _, exists := methodMap[method]; !exists {
			t.Errorf("route %q: method %s not documented in openapi.yaml", pattern, strings.ToUpper(method))
		}
	}
}
