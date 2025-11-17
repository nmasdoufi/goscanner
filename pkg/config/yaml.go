package config

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

type yamlParser struct {
	lines []string
	idx   int
}

func yamlToJSON(data []byte) ([]byte, error) {
	parser := &yamlParser{lines: preprocessYAML(data)}
	node, err := parser.parseBlock(0)
	if err != nil {
		return nil, err
	}
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(node); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

func preprocessYAML(data []byte) []string {
	lines := []string{}
	for _, raw := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if idx := strings.Index(raw, "#"); idx >= 0 {
			raw = raw[:idx]
		}
		lines = append(lines, strings.TrimRight(raw, " "))
	}
	return lines
}

func (p *yamlParser) parseBlock(indent int) (interface{}, error) {
	line, lineIndent, ok := p.peek()
	if !ok {
		return map[string]interface{}{}, nil
	}
	if lineIndent < indent {
		return map[string]interface{}{}, nil
	}
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "- ") {
		return p.parseSequence(indent)
	}
	return p.parseMap(indent)
}

func (p *yamlParser) parseMap(indent int) (map[string]interface{}, error) {
	result := map[string]interface{}{}
	for {
		line, lineIndent, ok := p.peek()
		if !ok || lineIndent < indent {
			break
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- ") {
			break
		}
		p.next()
		parts := strings.SplitN(trimmed, ":", 2)
		key := strings.TrimSpace(parts[0])
		var value interface{}
		if len(parts) == 2 {
			valueStr := strings.TrimSpace(parts[1])
			if valueStr != "" {
				value = parseScalar(valueStr)
				result[key] = value
				continue
			}
		}
		child, err := p.parseBlock(indent + 2)
		if err != nil {
			return nil, err
		}
		result[key] = child
	}
	return result, nil
}

func (p *yamlParser) parseSequence(indent int) ([]interface{}, error) {
	var result []interface{}
	for {
		line, lineIndent, ok := p.peek()
		if !ok || lineIndent < indent {
			break
		}
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- ") {
			break
		}
		p.next()
		valueStr := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
		if valueStr != "" {
			if item, ok, err := p.parseInlineMap(valueStr, indent); err != nil {
				return nil, err
			} else if ok {
				result = append(result, item)
				continue
			}
			result = append(result, parseScalar(valueStr))
			continue
		}
		child, err := p.parseBlock(indent + 2)
		if err != nil {
			return nil, err
		}
		result = append(result, child)
	}
	return result, nil
}

func (p *yamlParser) parseInlineMap(valueStr string, baseIndent int) (map[string]interface{}, bool, error) {
	idx := strings.Index(valueStr, ":")
	if idx <= 0 {
		return nil, false, nil
	}
	if idx+1 < len(valueStr) {
		next := valueStr[idx+1]
		if next != ' ' && next != '\t' {
			return nil, false, nil
		}
	}
	key := strings.TrimSpace(valueStr[:idx])
	if key == "" {
		return nil, false, nil
	}
	inlineVal := strings.TrimSpace(valueStr[idx+1:])
	item := map[string]interface{}{}
	if inlineVal != "" {
		item[key] = parseScalar(inlineVal)
	} else {
		child, err := p.parseBlock(baseIndent + 2)
		if err != nil {
			return nil, false, err
		}
		item[key] = child
	}
	extra, err := p.parseMap(baseIndent + 2)
	if err != nil {
		return nil, false, err
	}
	for k, v := range extra {
		item[k] = v
	}
	return item, true, nil
}

func (p *yamlParser) peek() (string, int, bool) {
	for p.idx < len(p.lines) {
		line := p.lines[p.idx]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			p.idx++
			continue
		}
		return line, countIndent(line), true
	}
	return "", 0, false
}

func (p *yamlParser) next() (string, int, bool) {
	line, indent, ok := p.peek()
	if ok {
		p.idx++
	}
	return line, indent, ok
}

func countIndent(line string) int {
	count := 0
	for _, r := range line {
		if r == ' ' {
			count++
			continue
		}
		break
	}
	return count
}

func parseScalar(value string) interface{} {
	if len(value) >= 2 {
		if strings.HasPrefix(value, "[") || strings.HasPrefix(value, "{") {
			var v interface{}
			if err := json.Unmarshal([]byte(value), &v); err == nil {
				return v
			}
		}
		if value[0] == '"' && value[len(value)-1] == '"' {
			return strings.Trim(value, "\"")
		}
	}
	switch strings.ToLower(value) {
	case "true":
		return true
	case "false":
		return false
	}
	if i, err := strconv.Atoi(value); err == nil {
		return i
	}
	return value
}
