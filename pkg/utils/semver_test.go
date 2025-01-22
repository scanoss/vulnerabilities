package utils

import "testing"

func TestStripSemverOperator(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "greater than operator",
			input:    ">2.3.0",
			expected: "2.3.0",
		},
		{
			name:     "greater than or equal operator",
			input:    ">=1.0.0",
			expected: "1.0.0",
		},
		{
			name:     "less than operator",
			input:    "<3.0.0",
			expected: "3.0.0",
		},
		{
			name:     "no operator",
			input:    "1.2.3",
			expected: "1.2.3",
		},
		{
			name:     "version with 'v'",
			input:    "v1.2.3",
			expected: "1.2.3",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := StripSemverOperator(tc.input)
			if result != tc.expected {
				t.Errorf("StripSemverOperator(%q) = %q, want %q",
					tc.input, result, tc.expected)
			}
		})
	}
}
