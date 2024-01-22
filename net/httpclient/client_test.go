package httpclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/DataDog/go-secure-sdk/net/httpclient/mock"
)

//nolint:bodyclose // No need to close the body in tests
func TestSafe(t *testing.T) {
	t.Parallel()
	// Get safe client
	c := Safe()

	var err error

	r1, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1/health", nil)
	_, err = c.Do(r1)
	assert.ErrorContains(t, err, `tcp4/127.0.0.1:80 is not authorized by the client: "127.0.0.1" address is loopback`)

	r2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	_, err = c.Do(r2)
	assert.ErrorContains(t, err, `tcp4/169.254.169.254:80 is not authorized by the client: "169.254.169.254" address is link local unicast`)

	r4, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://192.168.1.44:8600/v1/api", nil)
	_, err = c.Do(r4)
	assert.ErrorContains(t, err, `tcp4/192.168.1.44:8600 is not authorized by the client: "192.168.1.44" address is private`)
}

//nolint:bodyclose // No need to close the body in tests
func TestUnSafe_NoRedirect(t *testing.T) {
	t.Parallel()
	// Create a fake http server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "", http.StatusFound)
	}))

	// Get unsafe client
	c := UnSafe()

	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, mockServer.URL, nil)
	assert.NoError(t, err)

	resp, err := c.Do(r)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, resp.StatusCode, http.StatusFound)
}

//nolint:bodyclose // No need to close the body in tests
func TestUnSafe_MaxRedirect(t *testing.T) {
	t.Parallel()
	// Create a fake http server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "", http.StatusFound)
	}))

	// Get unsafe client
	c := UnSafe(
		WithFollowRedirect(true),
	)

	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, mockServer.URL, nil)
	assert.NoError(t, err)

	_, err = c.Do(r)
	assert.Error(t, err)
}

//nolint:bodyclose // No need to close the body in tests
func TestUnSafe_FilteredRedirect(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Prepare mocks
	authorizerMock := mock.NewMockAuthorizer(ctrl)
	authorizerMock.EXPECT().IsRequestAuthorized(gomock.Any()).Return(false)

	// Create a fake http server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))

	// Get unsafe client
	c := NewClient(
		authorizerMock,
		WithFollowRedirect(true),
		WithDisableResponseFilter(true),
	)

	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, mockServer.URL, nil)
	assert.NoError(t, err)

	resp, err := c.Do(r)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, resp.StatusCode, http.StatusForbidden)
	raw, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(raw), "Forbidden by client policy")
}

func Test_safeControl(t *testing.T) {
	t.Parallel()
	type args struct {
		network string
		address string
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*mock.MockAuthorizer)
		wantErr bool
	}{
		{
			name: "nil",
			prepare: func(ma *mock.MockAuthorizer) {
				ma.EXPECT().IsNetworkAddressAuthorized("", "").Return(false, nil)
			},
			wantErr: true,
		},
		{
			name: "blank address",
			args: args{
				network: "tcp4",
				address: "",
			},
			prepare: func(ma *mock.MockAuthorizer) {
				ma.EXPECT().IsNetworkAddressAuthorized("tcp4", "").Return(false, nil)
			},
			wantErr: true,
		},
		{
			name: "destination filtered",
			args: args{
				network: "tcp4",
				address: "8.8.8.8:453",
			},
			prepare: func(ma *mock.MockAuthorizer) {
				ma.EXPECT().IsNetworkAddressAuthorized("tcp4", "8.8.8.8:453").Return(false, nil)
			},
			wantErr: true,
		},
		{
			name: "destination filter error",
			args: args{
				network: "tcp4",
				address: "8.8.8.8:453",
			},
			prepare: func(ma *mock.MockAuthorizer) {
				ma.EXPECT().IsNetworkAddressAuthorized("tcp4", "8.8.8.8:453").Return(false, errors.New("test"))
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				network: "tcp4",
				address: "8.8.8.8:453",
			},
			prepare: func(ma *mock.MockAuthorizer) {
				ma.EXPECT().IsNetworkAddressAuthorized("tcp4", "8.8.8.8:453").Return(true, nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Prepare mocks
			authorizerMock := mock.NewMockAuthorizer(ctrl)
			if tt.prepare != nil {
				tt.prepare(authorizerMock)
			}

			underTest := safeControl(authorizerMock)

			err := underTest(tt.args.network, tt.args.address, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("safeControl() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
