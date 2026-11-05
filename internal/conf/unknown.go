package conf

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"
)

// unknownKeys returns the dotted paths of keys in data that no config field
// reads, such as a kcp option written at the wrong nesting level. Such keys
// are ignored, so reporting them is the only way users learn about typos.
func unknownKeys(data []byte) []string {
	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil // the real unmarshal reports syntax errors
	}
	var out []string
	walkKeys(raw, reflect.TypeFor[Conf](), "", &out)
	slices.Sort(out)
	return out
}

func walkKeys(node any, t reflect.Type, path string, out *[]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := node.(map[string]any)
		if !ok {
			return
		}
		fields := yamlFields(t)
		for k, v := range m {
			p := k
			if path != "" {
				p = path + "." + k
			}
			ft, ok := fields[k]
			if !ok {
				*out = append(*out, p)
				continue
			}
			walkKeys(v, ft, p, out)
		}
	case reflect.Slice:
		s, ok := node.([]any)
		if !ok {
			return
		}
		for i, v := range s {
			walkKeys(v, t.Elem(), fmt.Sprintf("%s[%d]", path, i), out)
		}
	}
}

// yamlFields maps the yaml key of every decoded field of struct t to its type.
func yamlFields(t reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, t.NumField())
	for f := range t.Fields() {
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		switch name {
		case "-":
			continue
		case "":
			name = strings.ToLower(f.Name)
		}
		fields[name] = f.Type
	}
	return fields
}
