//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
)

type rule struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) != 2 {
		fail("usage: go run check-public-policy-contract.go <gateway-policy.go> <deploy-install.sh>")
	}
	runtimeRules, err := readRuntimeRules(args[0])
	if err != nil {
		fail("read runtime rules: %v", err)
	}
	installerRules, err := readInstallerRules(args[1])
	if err != nil {
		fail("read installer rules: %v", err)
	}
	if len(runtimeRules) != len(installerRules) {
		fail("public systemd drop-in policy mismatch: runtime has %d rules, installer has %d", len(runtimeRules), len(installerRules))
	}
	for index := range runtimeRules {
		if runtimeRules[index] != installerRules[index] {
			fail("public systemd drop-in policy mismatch at %d: runtime %+v, installer %+v", index, runtimeRules[index], installerRules[index])
		}
	}
	fmt.Printf("public systemd drop-in policy matches: %d rules\n", len(runtimeRules))
}

func readRuntimeRules(path string) ([]rule, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}
	var rules []rule
	var found bool
	ast.Inspect(file, func(node ast.Node) bool {
		declaration, ok := node.(*ast.ValueSpec)
		if !ok || len(declaration.Names) != 1 || declaration.Names[0].Name != "requiredPublicSystemdDropins" || len(declaration.Values) != 1 {
			return true
		}
		found = true
		literal, ok := declaration.Values[0].(*ast.CompositeLit)
		if !ok {
			return false
		}
		for _, element := range literal.Elts {
			entry, ok := element.(*ast.CompositeLit)
			if !ok {
				continue
			}
			var current rule
			for _, field := range entry.Elts {
				pair, ok := field.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, keyOK := pair.Key.(*ast.Ident)
				value, valueOK := pair.Value.(*ast.BasicLit)
				if !keyOK || !valueOK || value.Kind != token.STRING {
					continue
				}
				decoded, decodeErr := strconv.Unquote(value.Value)
				if decodeErr != nil {
					continue
				}
				switch key.Name {
				case "ID":
					current.ID = decoded
				case "Path":
					current.Path = decoded
				}
			}
			rules = append(rules, current)
		}
		return false
	})
	if !found || len(rules) == 0 {
		return nil, fmt.Errorf("requiredPublicSystemdDropins declaration missing or empty")
	}
	for index, entry := range rules {
		if entry.ID == "" || entry.Path == "" {
			return nil, fmt.Errorf("runtime rule %d is incomplete", index)
		}
	}
	return rules, nil
}

func readInstallerRules(path string) ([]rule, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	const marker = "forbidden_path_entries='"
	before, after, found := strings.Cut(string(contents), marker)
	if !found || strings.Contains(before, marker) {
		return nil, fmt.Errorf("forbidden_path_entries declaration missing")
	}
	entries, _, found := strings.Cut(after, "'")
	if !found {
		return nil, fmt.Errorf("forbidden_path_entries closing quote missing")
	}
	var rules []rule
	if err := json.Unmarshal([]byte("["+entries+"]"), &rules); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("forbidden_path_entries is empty")
	}
	for index, entry := range rules {
		if entry.ID == "" || entry.Path == "" {
			return nil, fmt.Errorf("installer rule %d is incomplete", index)
		}
	}
	return rules, nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
