// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hubble

import (
	"errors"
	"fmt"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"google.golang.org/protobuf/encoding/protojson"
)

// ParseFlowFilters parses a whitespace-delimited list of JSON-encoded flow filters.
func ParseFlowFilters(arg string) ([]*flowpb.FlowFilter, error) {
	var filters []*flowpb.FlowFilter
	remaining := arg
	for {
		obj, rest, err := nextJSONObject(remaining)
		if err != nil {
			return nil, fmt.Errorf("failed to decode flow filters %q: %w", arg, err)
		}
		if obj == "" {
			break
		}
		filter := new(flowpb.FlowFilter)
		if err := protojson.Unmarshal([]byte(obj), filter); err != nil {
			return nil, fmt.Errorf("failed to decode flow filters %q: %w", arg, err)
		}
		filters = append(filters, filter)
		remaining = rest
	}
	return filters, nil
}

func nextJSONObject(s string) (obj, rest string, err error) {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	if i == len(s) {
		return "", "", nil
	}
	if s[i] != '{' {
		return "", "", fmt.Errorf("unexpected character %q looking for beginning of object", s[i])
	}

	start := i
	depth := 0
	inString := false

	for ; i < len(s); i++ {
		c := s[i]
		if inString {
			if c == '\\' {
				i++
				if i >= len(s) {
					return "", "", errors.New("unexpected EOF in string")
				}
			} else if c == '"' {
				inString = false
			}
			continue
		}

		switch c {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1], s[i+1:], nil
			}
		}
	}

	return "", "", errors.New("unexpected EOF")
}
