// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"sync/atomic"

	"github.com/DataDog/go-secure-sdk/log"
)

type atomicBool int32

func (b *atomicBool) isSet() bool { return atomic.LoadInt32((*int32)(b)) != 0 }
func (b *atomicBool) setTrue()    { atomic.StoreInt32((*int32)(b), 1) }
func (b *atomicBool) setFalse()   { atomic.StoreInt32((*int32)(b), 0) }

// -----------------------------------------------------------------------------

var devMode atomicBool

// InDevMode returns the development mode flag status.
func InDevMode() bool {
	return devMode.isSet()
}

// SetDevMode enables the local development mode in this package and returns a
// function to revert the configuration.
//
// Calling this method multiple times once the flag is enabled produces no effect.
func SetDevMode() (revert func()) {
	// Prevent multiple calls to indirectly disable the flag
	if devMode.isSet() {
		return func() {}
	}

	devMode.setTrue()
	log.Level(log.DebugLevel).Message("Secure SDK: Development mode enabled")

	return func() {
		devMode.setFalse()
		log.Level(log.DebugLevel).Message("Secure SDK: Development mode disabled")
	}
}

// -----------------------------------------------------------------------------

var fipsMode atomicBool

// InFIPSMode returns the FIPS compliance mode flag status.
func InFIPSMode() bool {
	return fipsMode.isSet()
}

// SetFIPSMode enables the FIPS compliance mode in this package and returns a
// function to revert the configuration.
//
// Calling this method multiple times once the flag is enabled produces no effect.
func SetFIPSMode() (revert func()) {
	// Prevent multiple calls to indirectly disable the flag
	if fipsMode.isSet() {
		return func() {}
	}

	fipsMode.setTrue()
	log.Level(log.DebugLevel).Message("Secure SDK: FIPS mode enabled")

	return func() {
		fipsMode.setFalse()
		log.Level(log.DebugLevel).Message("Secure SDK: FIPS mode disabled")
	}
}
