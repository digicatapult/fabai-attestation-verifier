//go:build js && wasm && sealtest

package main

import (
	"context"
	"encoding/json"
	"syscall/js"

	"github.com/digicatapult/fabai-attestation-verifier/internal/sealtest"
)

// registerTestHooks exports globalThis.fabaiSealTest.runVector(json), which
// runs one conformance vector and returns its outcome as JSON, so the Node.js
// and browser runners exercise the WASM build through JS.
func registerTestHooks() {
	hooks := js.Global().Get("Object").New()
	hooks.Set("runVector", js.FuncOf(func(_ js.Value, args []js.Value) any {
		input := stringArg(args, 0)
		return promise(func() (js.Value, error) {
			v, err := sealtest.Parse([]byte(input))
			if err != nil {
				return js.Undefined(), err
			}
			result, err := v.Run(context.Background())
			if err != nil {
				return js.Undefined(), err
			}
			data, err := json.Marshal(sealtest.OutcomeOf(result))
			if err != nil {
				return js.Undefined(), err
			}
			return js.ValueOf(string(data)), nil
		})
	}))
	js.Global().Set("fabaiSealTest", hooks)
}
