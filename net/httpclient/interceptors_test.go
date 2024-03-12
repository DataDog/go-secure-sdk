// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/DataDog/go-secure-sdk/net/httpclient/mock"
)

// -----------------------------------------------------------------------------

var defaultRoundTrip = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("OK")),
	}, nil
})

// -----------------------------------------------------------------------------

//nolint:bodyclose // No need to close the body in tests
func TestRequestFilter_Blocked(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Prepare mocks
	authorizerMock := mock.NewMockAuthorizer(ctrl)

	// Arm mock
	authorizerMock.EXPECT().IsRequestAuthorized(gomock.Any()).Return(false)

	underTest := NewRequestFilter(authorizerMock, defaultRoundTrip)
	res, err := underTest.RoundTrip(&http.Request{})

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, res.StatusCode, http.StatusForbidden)
	raw, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(raw), "Forbidden by client policy")
}

//nolint:bodyclose // No need to close the body in tests
func TestRequestFilter_Authorized(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Prepare mocks
	authorizerMock := mock.NewMockAuthorizer(ctrl)

	// Arm mock
	authorizerMock.EXPECT().IsRequestAuthorized(gomock.Any()).Return(true)

	underTest := NewRequestFilter(authorizerMock, defaultRoundTrip)
	res, err := underTest.RoundTrip(&http.Request{})

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, res.StatusCode, http.StatusOK)
	raw, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(raw), "OK")
}

//nolint:bodyclose // No need to close the body in tests
func TestResponseFilter_Blocked(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Prepare mocks
	authorizerMock := mock.NewMockAuthorizer(ctrl)

	// Arm mock
	authorizerMock.EXPECT().IsResponseAuthorized(gomock.Any()).Return(false)

	underTest := NewResponseFilter(authorizerMock, defaultRoundTrip)
	res, err := underTest.RoundTrip(&http.Request{})

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, res.StatusCode, http.StatusForbidden)
	raw, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(raw), "Forbidden by client policy")
}

//nolint:bodyclose // No need to close the body in tests
func TestResponseFilter_Authorized(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Prepare mocks
	authorizerMock := mock.NewMockAuthorizer(ctrl)

	// Arm mock
	authorizerMock.EXPECT().IsResponseAuthorized(gomock.Any()).Return(true)

	underTest := NewResponseFilter(authorizerMock, defaultRoundTrip)
	res, err := underTest.RoundTrip(&http.Request{})

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, res.StatusCode, http.StatusOK)
	raw, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(raw), "OK")
}
