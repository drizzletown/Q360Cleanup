//go:build windows

package main

import (
	"fmt"
	"q360cleanup/matcher"
	"syscall"
	"unsafe"
)

// Verify the authoritative MSI ProductName/Publisher before passing a GUID to
// msiexec /x. The uninstall-registry key alone can be forged/mismatched.
func checkMSIIdentity(productCode string) error {
	proc := syscall.NewLazyDLL("msi.dll").NewProc("MsiGetProductInfoW")
	get := func(property string) (string, error) {
		code := syscall.StringToUTF16Ptr(productCode)
		key := syscall.StringToUTF16Ptr(property)
		buf := make([]uint16, 32768)
		n := uint32(len(buf))
		result, _, _ := proc.Call(uintptr(unsafe.Pointer(code)), uintptr(unsafe.Pointer(key)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
		if result != 0 {
			return "", fmt.Errorf("MSI 查询 %s 返回代码 %d", property, result)
		}
		if int(n) >= len(buf) {
			return "", fmt.Errorf("MSI 产品属性 %s 异常过长", property)
		}
		return syscall.UTF16ToString(buf[:n]), nil
	}
	name, e := get("ProductName")
	if e != nil {
		return e
	}
	publisher, e := get("Publisher")
	if e != nil {
		return e
	}
	d := matcher.Classify(name, publisher)
	if !d.HighConfidence {
		return fmt.Errorf("MSI 原始产品身份不属于高可信 360 消费级产品（%q, %q），拒绝执行卸载", name, publisher)
	}
	return nil
}
