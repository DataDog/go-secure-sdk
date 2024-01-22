package password

import (
	"testing"

	fuzz "github.com/google/gofuzz"
)

func TestFromProfile(t *testing.T) {
	t.Parallel()
	type args struct {
		p *Profile
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "paranoid",
			args: args{
				p: ProfileParanoid,
			},
			wantErr: false,
		},
		{
			name: "noSymbol",
			args: args{
				p: ProfileNoSymbol,
			},
			wantErr: false,
		},
		{
			name: "strong",
			args: args{
				p: ProfileStrong,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := FromProfile(tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromProfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestPredefined(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		callable   func() (string, error)
		wantLength int
		wantErr    bool
	}{
		{
			name:       "paranoid",
			callable:   Paranoid,
			wantLength: ProfileParanoid.Length,
			wantErr:    false,
		},
		{
			name:       "strong",
			callable:   Strong,
			wantLength: ProfileStrong.Length,
			wantErr:    false,
		},
		{
			name:       "noSymbol",
			callable:   NoSymbol,
			wantLength: ProfileNoSymbol.Length,
			wantErr:    false,
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
			gotLength := len(got)
			if (tt.wantLength > 0) && tt.wantLength != gotLength {
				t.Errorf("Predefined() expected length = %v, got %v", tt.wantLength, gotLength)
				return
			}
		})
	}
}

// -----------------------------------------------------------------------------
//
//nolint:errcheck
func TestGenerate_Fuzz(t *testing.T) {
	t.Parallel()
	// Making sure that it never panics
	for i := 0; i < 50; i++ {
		f := fuzz.New()

		// Prepare arguments
		var (
			length, numDigits, numSymbol int
			noUpper, allowRepeat         bool
		)

		// Fuzz input
		f.Fuzz(&length)
		f.Fuzz(&numDigits)
		f.Fuzz(&numSymbol)
		f.Fuzz(&noUpper)
		f.Fuzz(&allowRepeat)

		// Execute
		Generate(length, numDigits, numSymbol, noUpper, allowRepeat)
	}
}

//nolint:errcheck
func TestFromProfile_Fuzz(t *testing.T) {
	t.Parallel()
	// Making sure that it never panics
	for i := 0; i < 50; i++ {
		f := fuzz.New()

		// Prepare arguments
		var p Profile

		// Fuzz input
		f.Fuzz(&p)

		// Execute
		FromProfile(&p)
	}
}
