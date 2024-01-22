package masking

import "testing"

func TestReserveMargin(t *testing.T) {
	t.Parallel()

	type args struct {
		value string
		n     int
		mask  string
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
			name: "negative count",
			args: args{
				value: "1234567890",
				n:     -1,
				mask:  "*",
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				value: "1234567890",
				n:     3,
				mask:  "*",
			},
			wantErr: false,
			wantRet: "123****890",
		},
		{
			name: "valid - default mask",
			args: args{
				value: "1234567890",
				n:     3,
				mask:  "",
			},
			wantErr: false,
			wantRet: "123****890",
		},
		{
			name: "valid - complete replace",
			args: args{
				value: "1234567890",
				n:     6,
				mask:  "*",
			},
			wantErr: false,
			wantRet: "**********",
		},
		{
			name: "valid - unicode",
			args: args{
				value: "コンニチハ",
				n:     1,
				mask:  "*",
			},
			wantErr: false,
			wantRet: "コ***ハ",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotRet, err := ReserveMargin(tt.args.value, tt.args.n, tt.args.mask)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReserveMargin() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotRet != tt.wantRet {
				t.Errorf("ReserveMargin() = %v, want %v", gotRet, tt.wantRet)
			}
		})
	}
}

func TestReserveRight(t *testing.T) {
	t.Parallel()

	type args struct {
		value string
		n     int
		mask  string
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
			name: "negative count",
			args: args{
				value: "1234567890",
				n:     -1,
				mask:  "*",
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				value: "1234567890",
				n:     3,
				mask:  "*",
			},
			wantErr: false,
			wantRet: "*******890",
		},
		{
			name: "valid - default mask",
			args: args{
				value: "1234567890",
				n:     3,
				mask:  "",
			},
			wantErr: false,
			wantRet: "*******890",
		},
		{
			name: "valid - unicode",
			args: args{
				value: "コンニチハ",
				n:     2,
				mask:  "*",
			},
			wantErr: false,
			wantRet: "***チハ",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotRet, err := ReserveRight(tt.args.value, tt.args.n, tt.args.mask)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReserveRight() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotRet != tt.wantRet {
				t.Errorf("ReserveRight() = %v, want %v", gotRet, tt.wantRet)
			}
		})
	}
}

func TestReserveLeft(t *testing.T) {
	t.Parallel()

	type args struct {
		value string
		n     int
		mask  string
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
			name: "negative count",
			args: args{
				value: "1234567890",
				n:     -1,
				mask:  "*",
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				value: "1234567890",
				n:     3,
				mask:  "*",
			},
			wantErr: false,
			wantRet: "123*******",
		},
		{
			name: "valid - default mask",
			args: args{
				value: "1234567890",
				n:     3,
				mask:  "",
			},
			wantErr: false,
			wantRet: "123*******",
		},
		{
			name: "valid - unicode",
			args: args{
				value: "コンニチハ",
				n:     2,
				mask:  "*",
			},
			wantErr: false,
			wantRet: "コン***",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotRet, err := ReserveLeft(tt.args.value, tt.args.n, tt.args.mask)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReserveLeft() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotRet != tt.wantRet {
				t.Errorf("ReserveLeft() = %v, want %v", gotRet, tt.wantRet)
			}
		})
	}
}
