package masking

import "testing"

func TestEmail(t *testing.T) {
	t.Parallel()

	type args struct {
		value string
	}
	tests := []struct {
		name    string
		args    args
		wantRet string
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: false,
			wantRet: "",
		},
		{
			name: "blank",
			args: args{
				value: "",
			},
			wantErr: false,
			wantRet: "",
		},
		{
			name: "valid",
			args: args{
				value: "firstname.lastname@datadoghq.com",
			},
			wantErr: false,
			wantRet: "f****************e@d***********m",
		},
		{
			name: "valid unicode",
			args: args{
				value: `χρήστης@παράδειγμα.ελ`,
			},
			wantErr: false,
			wantRet: "χ*****ς@π***********λ",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotRet, err := Email(tt.args.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Email() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotRet != tt.wantRet {
				t.Errorf("Email() = %v, want %v", gotRet, tt.wantRet)
			}
		})
	}
}
