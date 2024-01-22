package vault

import "testing"

func TestSanitizePath(t *testing.T) {
	t.Parallel()

	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "blank",
			args: args{
				s: "",
			},
			want: "",
		},
		{
			name: "whitespace prefixed",
			args: args{
				s: "  app/foo",
			},
			want: "app/foo",
		},
		{
			name: "whitespace suffixed",
			args: args{
				s: "app/foo   ",
			},
			want: "app/foo",
		},
		{
			name: "slash suffixed",
			args: args{
				s: "app/foo/",
			},
			want: "app/foo",
		},
		{
			name: "slash prefixed",
			args: args{
				s: "/app/foo",
			},
			want: "app/foo",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := sanitizePath(tt.args.s); got != tt.want {
				t.Errorf("SanitizePath() = %v, want %v", got, tt.want)
			}
		})
	}
}
