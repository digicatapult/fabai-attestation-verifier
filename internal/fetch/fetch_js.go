//go:build js

package fetch

import "net/http"

// setPlatformHeaders sets the options Go's js/wasm transport passes to the
// browser's fetch: it can't intercept redirects itself, so the browser must
// refuse them, and no cookies or credentials go with the request.
func setPlatformHeaders(req *http.Request) {
	req.Header.Set("js.fetch:redirect", "error")
	req.Header.Set("js.fetch:credentials", "omit")
}
