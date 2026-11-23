//go:build js && wasm

// Command fabai-seal-wasm is the seal check for the browser kiosk. It
// exports one function on globalThis.fabaiSeal:
//
//	check(baseURL, enclave) → Promise<result>
//
// The result is the Go library's Result as JSON, plus hpkeKey (a Uint8Array)
// only when all three ticks pass. The allowlist is embedded at build time
// from allowlist.json, after `fabai-seal allowlist verify` has checked its
// Sigstore bundle natively. Built without a list, every check fails with
// allowlist_unverified.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"syscall/js"

	"github.com/digicatapult/fabai-attestation-verifier/seal"
)

//go:embed allowlist.json
var embeddedAllowlist []byte

func main() {
	checker := seal.NewBuildVerified(embeddedAllowlist, seal.Options{})
	api := js.Global().Get("Object").New()
	api.Set("check", js.FuncOf(func(_ js.Value, args []js.Value) any {
		baseURL, enclave := stringArg(args, 0), stringArg(args, 1)
		return promise(func() (js.Value, error) {
			return toJS(checker.Check(context.Background(), seal.Target{BaseURL: baseURL, Enclave: enclave}))
		})
	}))
	js.Global().Set("fabaiSeal", api)
	registerTestHooks()
	select {}
}

func stringArg(args []js.Value, i int) string {
	if i < len(args) && args[i].Type() == js.TypeString {
		return args[i].String()
	}
	return ""
}

// toJS converts a result to a plain JS object, adding the key only when the
// result permits sending.
func toJS(r *seal.Result) (js.Value, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return js.Undefined(), err
	}
	obj := js.Global().Get("JSON").Call("parse", string(data))
	if key, ok := r.SendKey(); ok {
		array := js.Global().Get("Uint8Array").New(len(key))
		js.CopyBytesToJS(array, key)
		obj.Set("hpkeKey", array)
	}
	return obj, nil
}

// promise runs work on a goroutine, because a blocking call (the document
// request) can't run on the JS event loop's thread.
func promise(work func() (js.Value, error)) js.Value {
	executor := js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			value, err := work()
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}
			resolve.Invoke(value)
		}()
		return nil
	})
	defer executor.Release()
	return js.Global().Get("Promise").New(executor)
}
