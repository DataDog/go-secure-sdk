// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package hashutil

import (
	// Ensure a sane default import set for crypto hash builders
	_ "crypto/sha256"
	_ "crypto/sha512"
)

var maxHashContent = uint64(4 * 1024 * 1024 * 1024) // 4GB
