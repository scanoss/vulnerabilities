package utils

import (
	"regexp"
)

var operatorRegex = regexp.MustCompile(`^(>=|<=|~|v|>|<)`)

func StripSemverOperator(version string) string {
	return operatorRegex.ReplaceAllString(version, "")
}
