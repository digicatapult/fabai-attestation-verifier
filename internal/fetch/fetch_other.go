//go:build !js

package fetch

import "net/http"

// setPlatformHeaders is a no-op outside the browser: NewClient's
// CheckRedirect refuses redirects.
func setPlatformHeaders(*http.Request) {}
