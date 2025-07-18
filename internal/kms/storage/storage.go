/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

/*
Package storage implements storage backends for DEKs.

If an unset DEK is requested, the backend MUST return [ErrDEKUnset].
*/
package storage

import (
	"errors"
)

// ErrDEKUnset indicates if a key is not found in storage.
var ErrDEKUnset = errors.New("requested DEK not set")
