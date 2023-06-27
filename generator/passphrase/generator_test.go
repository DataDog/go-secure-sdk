// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package passphrase

import (
	"strings"
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/assert"
)

func TestDiceware(t *testing.T) {
	t.Parallel()
	type args struct {
		count int
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantCount int
	}{
		{
			name: "negative",
			args: args{
				count: -1,
			},
			wantErr:   false,
			wantCount: MinWordCount,
		},
		{
			name: "zero",
			args: args{
				count: 0,
			},
			wantErr:   false,
			wantCount: MinWordCount,
		},
		{
			name: "five",
			args: args{
				count: 5,
			},
			wantErr:   false,
			wantCount: 5,
		},
		{
			name: "upper limit",
			args: args{
				count: MaxWordCount + 1,
			},
			wantErr:   false,
			wantCount: MaxWordCount,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Diceware(tt.args.count)
			if (err != nil) != tt.wantErr {
				t.Errorf("Diceware() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			gotWordCount := len(strings.Split(got, "-"))
			if (tt.wantCount > 0) && tt.wantCount != gotWordCount {
				t.Errorf("Diceware() expected word count = %v, got %v", tt.wantCount, gotWordCount)
				return
			}
		})
	}
}

func TestPredefined(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		callable  func() (string, error)
		wantCount int
		wantErr   bool
	}{
		{
			name:      "basic",
			callable:  Basic,
			wantCount: BasicWordCount,
			wantErr:   false,
		},
		{
			name:      "strong",
			callable:  Strong,
			wantCount: StrongWordCount,
			wantErr:   false,
		},
		{
			name:      "paranoid",
			callable:  Paranoid,
			wantCount: ParanoidWordCount,
			wantErr:   false,
		},
		{
			name:      "master",
			callable:  Master,
			wantCount: MasterWordCount,
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.callable()
			if (err != nil) != tt.wantErr {
				t.Errorf("Predefined() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			gotWordCount := len(strings.Split(got, "-"))
			if (tt.wantCount > 0) && tt.wantCount != gotWordCount {
				t.Errorf("Predefined() expected word count = %v, got %v", tt.wantCount, gotWordCount)
				return
			}
		})
	}
}

// -----------------------------------------------------------------------------

func TestDiceware_Fuzz(t *testing.T) {
	t.Parallel()
	// Making sure that it never panics
	for i := 0; i < 50; i++ {
		f := fuzz.New()

		// Prepare arguments
		var wordCount int

		// Fuzz input
		f.Fuzz(&wordCount)

		// Execute
		_, err := Diceware(wordCount)
		assert.NoError(t, err)
	}
}
