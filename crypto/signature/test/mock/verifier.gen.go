// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/DataDog/go-secure-sdk/crypto/signature (interfaces: Verifier)

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"

	signature "github.com/DataDog/go-secure-sdk/crypto/signature"
)

// MockVerifier is a mock of Verifier interface.
type MockVerifier struct {
	ctrl     *gomock.Controller
	recorder *MockVerifierMockRecorder
}

// MockVerifierMockRecorder is the mock recorder for MockVerifier.
type MockVerifierMockRecorder struct {
	mock *MockVerifier
}

// NewMockVerifier creates a new mock instance.
func NewMockVerifier(ctrl *gomock.Controller) *MockVerifier {
	mock := &MockVerifier{ctrl: ctrl}
	mock.recorder = &MockVerifierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVerifier) EXPECT() *MockVerifierMockRecorder {
	return m.recorder
}

// Algorithm mocks base method.
func (m *MockVerifier) Algorithm() signature.Algorithm {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Algorithm")
	ret0, _ := ret[0].(signature.Algorithm)
	return ret0
}

// Algorithm indicates an expected call of Algorithm.
func (mr *MockVerifierMockRecorder) Algorithm() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Algorithm", reflect.TypeOf((*MockVerifier)(nil).Algorithm))
}

// PublicKey mocks base method.
func (m *MockVerifier) PublicKey() []byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PublicKey")
	ret0, _ := ret[0].([]byte)
	return ret0
}

// PublicKey indicates an expected call of PublicKey.
func (mr *MockVerifierMockRecorder) PublicKey() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PublicKey", reflect.TypeOf((*MockVerifier)(nil).PublicKey))
}

// Verify mocks base method.
func (m *MockVerifier) Verify(arg0, arg1 []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Verify indicates an expected call of Verify.
func (mr *MockVerifierMockRecorder) Verify(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockVerifier)(nil).Verify), arg0, arg1)
}
