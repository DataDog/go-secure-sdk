// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ssrfAuthorizer_IsNetworkAddressAuthorized(t *testing.T) {
	t.Parallel()
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
			name: "loopback - ipv4",
			args: args{
				network: "tcp4",
				address: "127.0.0.1:0",
			},
			wantErr: true,
		},
		{
			name: "loopback alternative - ipv4",
			args: args{
				network: "tcp4",
				address: "127.234.23.1:3000",
			},
			wantErr: true,
		},
		{
			name: "local unicast - ipv4",
			args: args{
				network: "tcp4",
				address: "169.254.169.254:8800",
			},
			wantErr: true,
		},
		{
			name: "private - ipv4",
			args: args{
				network: "tcp4",
				address: "192.168.1.14:80",
			},
			wantErr: true,
		},
		{
			name: "address without port",
			args: args{
				network: "tcp4",
				address: "192.168.1.14",
			},
			wantErr: true,
		},
		{
			name: "address without ip",
			args: args{
				network: "tcp4",
				address: "example.com:80",
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "ipv4",
			args: args{
				network: "tcp4",
				address: "8.8.8.8:453",
			},
			wantErr: false,
			want:    true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
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

func Test_ssrfAuthorizer_IsRequestAuthorized(t *testing.T) {
	t.Parallel()
	assert.True(t, DefaultAuthorizer.IsRequestAuthorized(nil))
}

func Test_ssrfAuthorizer_IsResponseAuthorized(t *testing.T) {
	t.Parallel()
	assert.True(t, DefaultAuthorizer.IsResponseAuthorized(nil))
}
