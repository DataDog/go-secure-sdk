package security

import (
	"log/slog"
	"sync/atomic"
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
	slog.Debug("Secure SDK: Development mode enabled")

	return func() {
		devMode.setFalse()
		slog.Debug("Secure SDK: Development mode disabled")
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
	slog.Debug("Secure SDK: FIPS mode enabled")

	return func() {
		fipsMode.setFalse()
		slog.Debug("Secure SDK: FIPS mode disabled")
	}
}
