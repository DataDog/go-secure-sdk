# Go Secure SDK

Package security provides various security-in-mind built features across
various domains.

The package is a part of the "Secure SDK" project.

It provides a set of libraries to mitigate common security issues and
vulnerabilities. The project is designed to be a one-stop-shop for security
features and libraries for Go developers.

The project is released to the public as a set of open-source libraries to
cover Datadog open-source projects.

The project is licensed under the Apache License, Version 2.0. The license
can be found in the LICENSE file in the root of the project.

## Sub Packages

* [compression](./compression): Package compression provides harded compression related features.

* [compression/archive](./compression/archive): Package archive provides high level compressed archive management features.

* [compression/archive/tar](./compression/archive/tar): Package tar provides TAR archive management functions

* [compression/archive/zip](./compression/archive/zip): Package zip provides hardened ZIP archive management functions

* [crypto/hashutil](./crypto/hashutil): Package hashutil provides secured cryptographic hash functions

* [generator/randomness](./generator/randomness): Package randomness provides `math/rand` dropin replace with secured initialization.

* [ioutil](./ioutil): Package ioutil provides I/O hardened operations.

* [ioutil/atomic](./ioutil/atomic): Package atomic provides atomic-level operations.

* [vfs](./vfs): Package vfs extends the default Golang FS abstraction to support secured write operations.
