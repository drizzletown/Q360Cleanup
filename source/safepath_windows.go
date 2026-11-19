//go:build windows

package main

import "q360cleanup/safecore"

func safecoreQuarantinable(path string, roots map[string]string) (string, bool) {
	return safecore.QuarantinableDir(path, roots)
}
