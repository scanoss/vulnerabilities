package utils

import (
	"regexp"
)

var operatorRegex = regexp.MustCompile(`^[<>=~^]+`)

func StripSemverOperator(version string) string {
	return operatorRegex.ReplaceAllString(version, "")
}
