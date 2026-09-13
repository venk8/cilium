// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package matchpattern

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/re"
)

const (
	// allowedDNSCharsREGroup is the regex group to match allowed characters in a DNS name.
	allowedDNSCharsREGroup = "[-a-zA-Z0-9_]"

	// dnsWildcardREGroup is the regex pattern for DNS wildcard specifier which matches one ore more
	// entire DNS labels. This regex group matches following cases:
	// * <dns-label>
	// * <dns-label-1>.<dns-label-2>.<dns-label-3>
	dnsWildcardREGroup = "(" + allowedDNSCharsREGroup + "+" + "([.]" + allowedDNSCharsREGroup + "+){0,})[.]"
)

var (
	// dnsWildcardRegex is regular expression to match a DNS wildcard.
	// For example this pattern will match: '*', '**', '**.', '***', '***.'
	dnsWildcardRegex = regexp.MustCompile("^[*]{1,}[.]?$")

	// allowedPatternChars tests that the MatchPattern field contains only the
	// characters we want in our wildcard scheme.
	allowedPatternChars = regexp.MustCompile("^[-a-zA-Z0-9_.*]+$") // the * inside the [] is a literal *

	// subdomainWildcardSpecifierPrefix is the regular expression to match subdomain wildcard prefix in dns patterns.
	// This regex will match '**[.]', '****[.]' and so on.
	subdomainWildcardSpecifierPrefix = regexp.MustCompile(`^[*]{2,}\[\.\]`)

	// wildcardSpecifier is the regular expression to match wildcard in DNS pattern.
	wildcardSpecifier = regexp.MustCompile("[*]{1,}")
)

// MatchAllAnchoredPattern is the simplest pattern that match all inputs. This resulting
// parsed regular expression is the same as an empty string regex (""), but this
// value is easier to reason about when serializing to and from json.
const MatchAllAnchoredPattern = "(?:)"

// MatchAllUnAnchoredPattern is the same as MatchAllAnchoredPattern, except that
// it can be or-ed (joined with "|") with other rules, and still match all rules.
const MatchAllUnAnchoredPattern = ".*"

// MaxFQDNLength is the maximum length of a MatchName or MatchPattern statement.
//
// Must be kept in sync with the validator for these fields in pkg/policy/api.
const MaxFQDNLength = 255

// Validate ensures that pattern is a parsable matchPattern. It returns the
// regexp generated when validating.
func Validate(pattern string) (matcher *regexp.Regexp, err error) {
	if err := prevalidate(pattern); err != nil {
		return nil, err
	}
	return re.CompileRegex(ToAnchoredRegexp(pattern))
}

// ValidateWithoutCache is the same as Validate() but doesn't consult the regex
// LRU.
func ValidateWithoutCache(pattern string) (matcher *regexp.Regexp, err error) {
	if err := prevalidate(pattern); err != nil {
		return nil, err
	}
	return regexp.Compile(ToAnchoredRegexp(pattern))
}

func prevalidate(pattern string) error {
	if len(strings.TrimSpace(pattern)) > MaxFQDNLength {
		return fmt.Errorf("Invalid MatchPattern: %q. Must be <= %d characters long.", pattern, MaxFQDNLength)
	}
	if len(pattern) > 0 && !hasOnlyAllowedPatternChars(pattern) {
		return fmt.Errorf("Invalid characters in MatchPattern: \"%s\". Only 0-9, a-z, A-Z and ., -, _ and * characters are allowed", pattern)
	}

	return nil
}

func isAllowedPatternChar(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.' || c == '*'
}

func hasOnlyAllowedPatternChars(pattern string) bool {
	for i := 0; i < len(pattern); i++ {
		if !isAllowedPatternChar(pattern[i]) {
			return false
		}
	}
	return true
}

func isDNSWildcard(pattern string) bool {
	if len(pattern) == 0 {
		return false
	}
	if pattern[len(pattern)-1] == '.' {
		pattern = pattern[:len(pattern)-1]
		if len(pattern) == 0 {
			return false
		}
	}
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '*' {
			return false
		}
	}
	return true
}

// Sanitize canonicalized the pattern for use by ToAnchoredRegexp
func Sanitize(pattern string) string {
	if isDNSWildcard(pattern) {
		return pattern
	}

	return dns.FQDN(pattern)
}

// ToAnchoredRegexp converts a MatchPattern field into a regexp string. It does not
// validate the pattern. It also adds anchors to ensure it match the whole string.
// It supports:
// * to select 0 or more DNS valid characters
func ToAnchoredRegexp(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.ToLower(pattern)

	// handle the * match-all case. This will filter down to the end.
	if isDNSWildcard(pattern) {
		return "(^(" + allowedDNSCharsREGroup + "+[.])+$)|(^[.]$)"
	}

	pattern = escapeRegexpCharacters(pattern)

	// Anchor the match to require the whole string to match this expression
	return "^" + pattern + "$"
}

// ToUnAnchoredRegexp converts a MatchPattern field into a regexp string. It does not
// validate the pattern. It does not add regexp anchors.
// It supports:
// * to select 0 or more DNS valid characters
func ToUnAnchoredRegexp(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.ToLower(pattern)

	// handle the * match-all case. This will filter down to the end.
	if isDNSWildcard(pattern) {
		return MatchAllUnAnchoredPattern
	}

	pattern = escapeRegexpCharacters(pattern)
	return pattern
}

func escapeRegexpCharacters(pattern string) string {
	var b strings.Builder
	b.Grow(len(pattern)*3 + len(dnsWildcardREGroup))

	start := 0
	leadingStars := 0
	for leadingStars < len(pattern) && pattern[leadingStars] == '*' {
		leadingStars++
	}
	if leadingStars >= 2 && leadingStars < len(pattern) && pattern[leadingStars] == '.' {
		b.WriteString(dnsWildcardREGroup)
		start = leadingStars + 1
	}

	for i := start; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '.':
			b.WriteString("[.]")
		case '*':
			for i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
			}
			b.WriteString(allowedDNSCharsREGroup)
			b.WriteByte('*')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
