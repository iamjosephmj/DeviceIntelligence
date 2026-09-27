package tokens

import "errors"

// Package-local sentinels for the token envelope and key loading paths.
// Callers compare identity, so these are values, not wrapped strings.
type hexError string

func (e hexError) Error() string { return string(e) }

var (
	errNotV2    = errors.New("not a v2 token")
	errTooShort = errors.New("v2 token too short")
)
