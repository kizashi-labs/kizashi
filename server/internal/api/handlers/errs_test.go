package handlers

import "testing"

func TestIsValidUUID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid lowercase UUID v4",
			input: "550e8400-e29b-41d4-a716-446655440000",
			want:  true,
		},
		{
			name:  "valid uppercase UUID",
			input: "550E8400-E29B-41D4-A716-446655440000",
			want:  true,
		},
		{
			name:  "valid mixed-case UUID",
			input: "550e8400-E29B-41d4-A716-446655440000",
			want:  true,
		},
		{
			name:  "too short",
			input: "550e8400-e29b-41d4-a716-44665544000",
			want:  false,
		},
		{
			name:  "too long",
			input: "550e8400-e29b-41d4-a716-4466554400000",
			want:  false,
		},
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
		{
			name:  "invalid character in hex segment",
			input: "550e8400-e29b-41d4-a716-44665544000g",
			want:  false,
		},
		{
			name:  "dash in wrong position (position 9 instead of 8)",
			input: "550e8400e-29b-41d4-a716-446655440000",
			want:  false,
		},
		{
			name:  "missing dash at position 8",
			input: "550e8400Xe29b-41d4-a716-446655440000",
			want:  false,
		},
		{
			name:  "all zeros UUID",
			input: "00000000-0000-0000-0000-000000000000",
			want:  true,
		},
		{
			name:  "all dashes replaced with other char",
			input: "550e8400Xe29bX41d4Xa716X446655440000",
			want:  false,
		},
		{
			name:  "spaces instead of dashes",
			input: "550e8400 e29b 41d4 a716 446655440000",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidUUID(tt.input)
			if got != tt.want {
				t.Errorf("isValidUUID(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
