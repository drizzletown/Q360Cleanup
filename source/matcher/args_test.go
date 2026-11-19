package matcher

import (
	"reflect"
	"testing"
)

func TestParseWindowsCommandLine(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{`"C:\Program Files (x86)\360\360Safe\uninst.exe" /uninstall`, []string{`C:\Program Files (x86)\360\360Safe\uninst.exe`, `/uninstall`}},
		{`C:\360\uninst.exe /U`, []string{`C:\360\uninst.exe`, `/U`}},
		{`"C:\360\uninst.exe" "/quiet option"`, []string{`C:\360\uninst.exe`, `/quiet option`}},
		{`"C:\dir\uninst.exe" "two ""quotes"""`, []string{`C:\dir\uninst.exe`, `two "quotes"`}},
		{`   "C:\x y\uninstall.exe"   --remove  `, []string{`C:\x y\uninstall.exe`, `--remove`}},
		{``, []string{}},
	}
	for _, tt := range tests {
		got := ParseWindowsCommandLine(tt.input)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: got %#v want %#v", tt.input, got, tt.want)
		}
	}
}
