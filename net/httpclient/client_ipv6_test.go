package httpclient

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

//nolint:bodyclose // No need to close the body in tests
func TestSafeIPv6(t *testing.T) {
	// Get safe client
	c := Safe()

	var err error

	r3, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://[fd00:ec2::254]/latest/meta-data/", nil)
	_, err = c.Do(r3)
	assert.ErrorContains(t, err, `tcp6/[fd00:ec2::254]:80 is not authorized by the client: "fd00:ec2::254" address is private`)
}

func Test_ssrfAuthorizer_IsNetworkAddressAuthorizedIPv6(t *testing.T) {
	type args struct {
		network string
		address string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "local unicast - ipv6",
			args: args{
				network: "tcp6",
				address: "[fe80::200:5aee:feaa:20a2]:443",
			},
			wantErr: true,
		},
		{
			name: "private - ipv6",
			args: args{
				network: "tcp6",
				address: "[fd00:ec2::254]:53",
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "ipv6",
			args: args{
				network: "tcp6",
				address: "[2001:4860:4860:0:0:0:0:1]:8888",
			},
			wantErr: false,
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			az := DefaultAuthorizer
			got, err := az.IsNetworkAddressAuthorized(tt.args.network, tt.args.address)
			if (err != nil) != tt.wantErr {
				t.Errorf("ssrfAuthorizer.IsNetworkAddressAuthorized() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ssrfAuthorizer.IsNetworkAddressAuthorized() = %v, want %v", got, tt.want)
			}
		})
	}
}
