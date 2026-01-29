package middleware

import (
	"testing"
)

func TestAnonymize(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"short", "abc", "***"},
		{"eight", "12345678", "***"},
		{"long", "1234567890", "1234***"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Anonymize(tt.input)
			if got != tt.want {
				t.Errorf("Anonymize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
