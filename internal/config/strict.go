package config

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/rknightion/graph2otel/internal/teams/quality"
	"go.yaml.in/yaml/v4"
)

const removedCardinalityMetricLimit = "cardinality.metric_limit"

// validateYAMLFile rejects unknown keys before koanf merges the document with
// defaults or environment overrides. That order matters: once koanf has
// flattened and merged the layers, an unknown key can disappear during typed
// decode and its original sequence index is no longer recoverable.
func validateYAMLFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	if len(doc.Content) == 0 {
		return nil
	}
	if err := validateYAMLNode(doc.Content[0], reflect.TypeOf(Config{}), ""); err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	return nil
}

func validateYAMLNode(node *yaml.Node, typ reflect.Type, path string) error {
	node = dereferenceAlias(node)
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	switch typ.Kind() {
	case reflect.Struct:
		isTeams := typ == reflect.TypeFor[TeamsConfig]() || typ == reflect.TypeFor[TeamsGeoIPConfig]()
		isThresholds := typ == reflect.TypeFor[quality.Thresholds]()
		if typ == reflect.TypeFor[VAACConfig]() {
			// Do not let the weak typed decoder format a pasted credential in
			// a shape error or coerce a string into an opt-in.
			if node.Kind != yaml.MappingNode {
				return fmt.Errorf("%s: expected a mapping", path)
			}
			for i := 0; i+1 < len(node.Content); i += 2 {
				key, value := node.Content[i].Value, dereferenceAlias(node.Content[i+1])
				switch key {
				case "enabled":
					if value.Kind != yaml.ScalarNode || value.Tag != "!!bool" {
						return fmt.Errorf("%s.enabled: expected a boolean", path)
					}
				case "username_file", "password_file":
					if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
						return fmt.Errorf("%s.%s: expected a file path string", path, key)
					}
				default:
					return fmt.Errorf("%s: unknown key; only enabled, username_file and password_file are accepted", path)
				}
			}
		}
		if typ == reflect.TypeFor[AdminAPIConfig]() {
			if node.Kind != yaml.MappingNode {
				return fmt.Errorf("%s: expected a mapping", path)
			}
			for i := 0; i+1 < len(node.Content); i += 2 {
				key, value := node.Content[i].Value, dereferenceAlias(node.Content[i+1])
				if key != "enabled" {
					return fmt.Errorf("%s: unknown key; only enabled is accepted", path)
				}
				if value.Kind != yaml.ScalarNode || value.Tag != "!!bool" {
					return fmt.Errorf("%s.enabled: expected a boolean", path)
				}
			}
		}
		if node.Kind != yaml.MappingNode {
			if isTeams || isThresholds || typ == reflect.TypeFor[TeamsQualityConfig]() {
				return fmt.Errorf("%s: expected a mapping", path)
			}
			return nil // typed decode owns other value-shape diagnostics
		}
		fields := yamlStructFields(typ)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			fieldPath := joinConfigPath(path, key.Value)
			fieldType, ok := fields[key.Value]
			if !ok {
				// Preserve the targeted migration diagnostic for the one
				// deliberately removed key. Load checks it before decode.
				if fieldPath == removedCardinalityMetricLimit {
					continue
				}
				return fmt.Errorf("unknown configuration key %s", fieldPath)
			}
			// Koanf uses weak decoding for the environment layer. Do not let
			// it turn Teams YAML numbers or scalars into paths or rules.
			if isTeams {
				if err := validateTeamsField(value, fieldType.Kind(), fieldPath); err != nil {
					return err
				}
			}
			if isThresholds {
				tag := dereferenceAlias(value).ShortTag()
				switch {
				case fieldType.Kind() == reflect.Int64:
					var count int64
					if tag != "!!int" || value.Decode(&count) != nil {
						return fmt.Errorf("%s: expected an integer", fieldPath)
					}
				case tag != "!!int" && tag != "!!float":
					return fmt.Errorf("%s: expected a number", fieldPath)
				}
			}
			if err := validateYAMLNode(value, fieldType, fieldPath); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		// Weak decode accepts a singleton tenant mapping as a one-element
		// list. Walk that element too, so no supported form skips validation.
		if path == "tenants" && node.Kind == yaml.MappingNode {
			return validateYAMLNode(node, typ.Elem(), "tenants[0]")
		}
		if strings.HasPrefix(path, "tenants[") && strings.HasSuffix(path, "].o365_activity.record_type_allow_list") {
			return validateO365RecordTypeAllowList(node, path)
		}
		if node.Kind != yaml.SequenceNode {
			if path == "profiles" || (strings.HasPrefix(path, "tenants[") && strings.HasSuffix(path, "].profiles")) {
				return fmt.Errorf("%s: expected a list of profiles", path)
			}
			return nil
		}
		for i, item := range node.Content {
			if err := validateYAMLNode(item, typ.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		if node.Kind != yaml.MappingNode {
			return nil
		}
		// Map keys are intentional extension points. Their values still follow
		// the declared type: collector values are closed CollectorConfig
		// objects, while map[string]string tags remain fully open.
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			itemPath := path + "[" + strconv.Quote(key.Value) + "]"
			if err := validateYAMLNode(value, typ.Elem(), itemPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateTeamsField(node *yaml.Node, kind reflect.Kind, path string) error {
	node = dereferenceAlias(node)
	switch kind {
	case reflect.String:
		if node.ShortTag() != "!!str" {
			return fmt.Errorf("%s: expected a string", path)
		}
	case reflect.Slice:
		if node.Kind != yaml.SequenceNode {
			return fmt.Errorf("%s: expected a list of strings", path)
		}
		for i, item := range node.Content {
			if dereferenceAlias(item).ShortTag() != "!!str" {
				return fmt.Errorf("%s[%d]: expected a string", path, i)
			}
		}
	}
	return nil
}

// validateO365RecordTypeAllowList prevents weak config decoding from silently
// truncating a fractional ID or coercing a scalar to a one-item list.
func validateO365RecordTypeAllowList(node *yaml.Node, path string) error {
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("%s: expected a list of positive integer record type IDs", path)
	}
	for i, raw := range node.Content {
		item := dereferenceAlias(raw)
		var id int64
		if item.ShortTag() != "!!int" || item.Decode(&id) != nil || id <= 0 {
			return fmt.Errorf("%s[%d]: expected a positive integer record type ID", path, i)
		}
	}
	return nil
}

func yamlStructFields(typ reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}
		name := strings.Split(field.Tag.Get("yaml"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		fields[name] = field.Type
	}
	return fields
}

func dereferenceAlias(node *yaml.Node) *yaml.Node {
	for node != nil && node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	return node
}

func joinConfigPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + keyDelim + key
}

// ValidateCollectorOverrides checks the registry-dependent portion of config
// validation without importing collectors into this package. Callers supply
// the complete runtime collector-name set and the Graph/blob intersection.
func (c *Config) ValidateCollectorOverrides(knownNames, sourceSwitchable map[string]bool) error {
	if c == nil {
		return nil
	}
	if err := c.validateCollectorMap(c.Collectors, "collectors", knownNames, sourceSwitchable); err != nil {
		return err
	}
	for i := range c.Tenants {
		prefix := fmt.Sprintf("tenants[%d].collectors", i)
		if err := c.validateCollectorMap(
			c.Tenants[i].Collectors,
			prefix,
			knownNames,
			sourceSwitchable,
		); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) validateCollectorMap(
	overrides map[string]CollectorConfig,
	prefix string,
	knownNames map[string]bool,
	sourceSwitchable map[string]bool,
) error {
	names := make([]string, 0, len(overrides))
	for name := range overrides {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		override := overrides[name]
		basePath := prefix + "[" + strconv.Quote(name) + "]"
		if !knownNames[name] {
			ref := c.collectorOrigin(basePath)
			if suggestion := collectorNameSuggestion(name, knownNames); suggestion != "" {
				return fmt.Errorf("%s: unknown collector; did you mean %q", ref, suggestion)
			}
			return fmt.Errorf("%s: unknown collector", ref)
		}
		if err := validateInterval(override.Interval); err != nil {
			path := basePath + keyDelim + "interval"
			return fmt.Errorf("%s: %w", c.collectorOrigin(path), err)
		}
		if override.Source == "" {
			continue
		}
		sourcePath := c.collectorOrigin(basePath + keyDelim + "source")
		if override.Source != "graph" && override.Source != "blob" {
			return fmt.Errorf("%s: source must be exactly graph or blob", sourcePath)
		}
		if !sourceSwitchable[name] {
			return fmt.Errorf("%s: source is only valid for a source-switchable collector", sourcePath)
		}
	}
	return nil
}

func (c *Config) collectorOrigin(path string) string {
	if origin := c.collectorEnvOrigins[path]; origin != "" {
		return origin
	}
	return path
}

func collectorNameSuggestion(unknown string, knownNames map[string]bool) string {
	names := make([]string, 0, len(knownNames))
	for name, known := range knownNames {
		if known {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	bestName := ""
	bestDistance := -1
	tied := false
	for _, name := range names {
		distance := editDistance(unknown, name)
		switch {
		case bestDistance == -1 || distance < bestDistance:
			bestName = name
			bestDistance = distance
			tied = false
		case distance == bestDistance:
			tied = true
		}
	}
	if tied || bestDistance < 0 || bestDistance > suggestionDistanceLimit(unknown) {
		return ""
	}
	return bestName
}

func suggestionDistanceLimit(name string) int {
	switch length := len([]rune(name)); {
	case length <= 4:
		return 1
	case length <= 12:
		return 2
	default:
		return 3
	}
}

func editDistance(a, b string) int {
	ar, br := []rune(a), []rune(b)
	previous := make([]int, len(br)+1)
	for j := range previous {
		previous[j] = j
	}
	for i, left := range ar {
		current := make([]int, len(br)+1)
		current[0] = i + 1
		for j, right := range br {
			cost := 0
			if left != right {
				cost = 1
			}
			current[j+1] = min(
				current[j]+1,
				previous[j+1]+1,
				previous[j]+cost,
			)
		}
		previous = current
	}
	return previous[len(br)]
}
