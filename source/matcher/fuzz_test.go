package matcher

import "testing"

func FuzzMSICommandNoArbitraryExecutable(f *testing.F) {
	for _, s := range []string{
		`cmd.exe /c msiexec /x{ABCDEF12-1111-2222-3333-123456789ABC}`,
		`msiexec.exe /x {ABCDEF12-1111-2222-3333-123456789ABC}`,
		`powershell.exe -Command msiexec.exe /x {ABCDEF12-1111-2222-3333-123456789ABC}`,
		`"C:\Windows\System32\msiexec.exe" /i {ABCDEF12-1111-2222-3333-123456789ABC}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, command string) {
		if len(command) > 4096 {
			t.Skip()
		}
		code := MSIProductCode("any", command, false)
		if code == "" {
			return
		}
		args := ParseWindowsCommandLine(command)
		if len(args) < 2 {
			t.Fatalf("accepted malformed command %q", command)
		}
		if !guidPattern.MatchString(code) {
			t.Fatalf("accepted malformed GUID %q", code)
		}
	})
}
func FuzzClassifyDoesNotAcceptOtherBrand(f *testing.F) {
	for _, x := range []string{"Fusion 360", "Xbox 360", "Microsoft 365", "360安全卫士", "360度摄影"} {
		f.Add(x)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > 8192 {
			t.Skip()
		}
		d := Classify(name, "Autodesk")
		if d.HighConfidence {
			t.Fatalf("untrusted publisher high confidence: %q", name)
		}
	})
}
