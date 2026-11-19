package matcher

import "testing"

func TestClassification(t *testing.T) {
	test := []struct {
		name, publisher   string
		match, confidence bool
	}{
		{"360安全卫士", "北京奇虎科技有限公司", true, true},
		{"360杀毒", "360 Security", true, true},
		{"360极速浏览器X", "", true, false},
		{"360压缩", "", true, false},
		{"360壁纸", "三六零安全科技", true, true},
		{"Qihoo 360 Total Security", "Qihoo 360", true, true},
		{"360企业安全云", "奇虎", false, false},
		{"360天擎终端安全", "奇虎", false, false},
		{"Microsoft 365", "Microsoft", false, false},
		{"Fusion 360", "Autodesk", false, false},
		{"Xbox 360 Controller", "Microsoft", false, false},
		{"360度全景软件", "未知公司", false, false},
		{"360驱动大师", "陌生发布者", true, false},
		{"360智能系统", "Qihoo", true, false},
		{"360度安全管理平台", "Somecorp", false, false},
	}
	for _, tt := range test {
		got := Classify(tt.name, tt.publisher)
		if got.Match != tt.match || got.HighConfidence != tt.confidence {
			t.Errorf("%q by %q got %+v expected %v,%v", tt.name, tt.publisher, got, tt.match, tt.confidence)
		}
	}
}
func TestMSI(t *testing.T) {
	g := "{6BA4F2FC-F51C-472A-9ED2-5548916A6B9D}"
	if got := MSIProductCode(g, "", true); got != g {
		t.Fatal(got)
	}
	if got := MSIProductCode("Any", "MsiExec.exe /I"+g, false); got != g {
		t.Fatal(got)
	}
	if got := MSIProductCode("Any", "evil.exe /I"+g, false); got != "" {
		t.Fatal("accepted untrusted exe")
	}
}
func TestExeGuard(t *testing.T) {
	for _, s := range []string{"cmd.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe", "update.exe", "foo.bat"} {
		if SafeUninstallerBase(s) {
			t.Errorf("accepted %s", s)
		}
	}
	for _, s := range []string{"uninst.exe", "uninstall.exe", "setup.exe"} {
		if !SafeUninstallerBase(s) {
			t.Errorf("rejected %s", s)
		}
	}
}

func TestPlausible360Path(t *testing.T) {
	for _, s := range []string{`C:\Program Files (x86)\360\360Safe\uninst.exe`, `D:\360se6\Uninstall.exe`, `C:\Program Files\Qihoo 360\setup.exe`} {
		if !Plausible360Path(s) {
			t.Errorf("rejected %q", s)
		}
	}
	for _, s := range []string{`C:\Windows\System32\setup.exe`, `C:\Temp\setup.exe`, `C:\OtherApp\uninst.exe`} {
		if Plausible360Path(s) {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestMSIRejectsExecutableSmuggling(t *testing.T) {
	g := "{6BA4F2FC-F51C-472A-9ED2-5548916A6B9D}"
	for _, cmd := range []string{
		`evil.exe C:\Windows\System32\msiexec.exe /x` + g,
		`C:\Temp\msiexec.exe /x` + g,
		`cmd.exe /c msiexec.exe /x` + g,
		`powershell.exe -Command "msiexec.exe /x` + g + `"`,
		`msiexec.exe /q` + g,
		`msiexec.exe /x` + g + ` /x{00000000-0000-0000-0000-000000000001}`,
		`msiexec.exe /x {00000000-0000-0000-0000-000000000001} /i ` + g,
	} {
		if c := MSIProductCode("not-a-guid", cmd, false); c != "" {
			t.Errorf("smuggled MSI code %s from %q", c, cmd)
		}
	}
	for _, cmd := range []string{`MsiExec.exe /I` + g, `"C:\Windows\System32\msiexec.exe" /X ` + g, `msiexec /x ` + g} {
		if c := MSIProductCode("", cmd, false); c != g {
			t.Errorf("missed %q: %q", cmd, c)
		}
	}
}

func TestVendorPathRejectsLookalikes(t *testing.T) {
	for _, path := range []string{
		`C:\Downloads\360backup\setup.exe`,
		`C:\Autodesk\Fusion 360\setup.exe`,
		`C:\something\360photo\uninstall.exe`,
		`C:\Apps\other\setup360safe.exe`,
	} {
		if Plausible360Path(path) {
			t.Errorf("false vendor path %q", path)
		}
	}
}
