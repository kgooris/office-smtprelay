// Package i18n provides the English and Dutch texts of the web UI.
//
// Texts live in en.json and nl.json (flat key -> text). English is the
// fallback for a missing translation; a missing key renders as the key itself.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed en.json nl.json
var files embed.FS

// Languages lists the supported language codes. The first is the fallback.
var Languages = []string{"en", "nl"}

// Catalog holds all texts.
type Catalog struct {
	msgs map[string]map[string]string
}

// Load reads the embedded catalogs.
func Load() (*Catalog, error) {
	c := &Catalog{msgs: map[string]map[string]string{}}
	for _, lang := range Languages {
		b, err := files.ReadFile(lang + ".json")
		if err != nil {
			return nil, err
		}
		m := map[string]string{}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("i18n: %s.json: %w", lang, err)
		}
		c.msgs[lang] = m
	}
	return c, nil
}

// Supported reports whether lang is a known language code.
func Supported(lang string) bool {
	for _, l := range Languages {
		if l == lang {
			return true
		}
	}
	return false
}

// T returns the text for key in lang. Format arguments are applied with
// fmt.Sprintf when given.
func (c *Catalog) T(lang, key string, args ...any) string {
	s, ok := c.msgs[lang][key]
	if !ok {
		if s, ok = c.msgs[Languages[0]][key]; !ok {
			return key
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// Has reports whether key exists in lang (without fallback).
func (c *Catalog) Has(lang, key string) bool {
	_, ok := c.msgs[lang][key]
	return ok
}

// Keys returns the sorted keys of a language, optionally filtered by prefix.
func (c *Catalog) Keys(lang, prefix string) []string {
	var out []string
	for k := range c.msgs[lang] {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
