//go:build js && wasm && !sealtest

package main

// registerTestHooks does nothing in release builds: the conformance-vector
// hooks exist only with the sealtest tag.
func registerTestHooks() {}
