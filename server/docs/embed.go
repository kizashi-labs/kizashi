// Package docs provides the embedded OpenAPI specification for the EDR Platform API.
package docs

import _ "embed"

// Spec is the OpenAPI 3.0 specification embedded at compile time.
//
//go:embed openapi.yaml
var Spec []byte
