//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"q360cleanup/safecore"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	WM_CREATE           = 0x0001
	WM_DESTROY          = 0x0002
	WM_SIZE             = 0x0005
	WM_COMMAND          = 0x0111
	WM_SETFONT          = 0x0030
	WM_APP_EVENT        = 0x8001
	WS_OVERLAPPEDWINDOW = 0x00CF0000
	WS_VISIBLE          = 0x10000000
	WS_CHILD            = 0x40000000
	WS_VSCROLL          = 0x00200000
	WS_TABSTOP          = 0x00010000
	WS_BORDER           = 0x00800000
	LBS_EXTENDEDSEL     = 0x0800
	ES_MULTILINE        = 0x0004
	ES_AUTOVSCROLL      = 0x0040
	ES_READONLY         = 0x0800
	WM_USER             = 0x0400
	LB_ADDSTRING        = 0x0180
	LB_RESETCONTENT     = 0x0184
	LB_GETSELCOUNT      = 0x0190
	LB_GETSELITEMS      = 0x0191
	EM_SETSEL           = 0x00B1
	EM_REPLACESEL       = 0x00C2
	MB_OK               = 0x0000
	MB_YESNO            = 0x0004
	MB_ICONWARNING      = 0x0030
	MB_ICONINFORMATION  = 0x0040
	MB_DEFBUTTON2       = 0x0100
	BN_CLICKED          = 0
	BTN_SCAN            = 101
	BTN_UNINSTALL       = 102
	BTN_REMAINS         = 103
	BTN_REPORT          = 104
	BTN_APPS            = 105
	BTN_ISOLATE         = 106
	BTN_RESTORE         = 107
	BTN_VERIFY          = 108
)

var (
	user32                                                                                   = syscall.NewLazyDLL("user32.dll")
	kernel32                                                                                 = syscall.NewLazyDLL("kernel32.dll")
	gdi32                                                                                    = syscall.NewLazyDLL("gdi32.dll")
	procRegClass                                                                             = user32.NewProc("RegisterClassExW")
	procCreate                                                                               = user32.NewProc("CreateWindowExW")
	procDef                                                                                  = user32.NewProc("DefWindowProcW")
	procSend                                                                                 = user32.NewProc("SendMessageW")
	procPost                                                                                 = user32.NewProc("PostMessageW")
	procMsgBox                                                                               = user32.NewProc("MessageBoxW")
	procMove                                                                                 = user32.NewProc("MoveWindow")
	procGetMessage                                                                           = user32.NewProc("GetMessageW")
	procTranslate                                                                            = user32.NewProc("TranslateMessage")
	procDispatch                                                                             = user32.NewProc("DispatchMessageW")
	procShow                                                                                 = user32.NewProc("ShowWindow")
	procUpdate                                                                               = user32.NewProc("UpdateWindow")
	procPostQuit                                                                             = user32.NewProc("PostQuitMessage")
	procSetText                                                                              = user32.NewProc("SetWindowTextW")
	procEnable                                                                               = user32.NewProc("EnableWindow")
	hwndMain, hwndHeader, hwndDesc, hwndList, hwndLog, hwndStatus, hwndLogLabel              uintptr
	btnScan, btnUninstall, btnRemains, btnReport, btnApps, btnIsolate, btnRestore, btnVerify uintptr
	uiFont                                                                                   uintptr
	apps                                                                                     []appEntry
	viewMode                                                                                 = "apps"
	auditCurrent                                                                             *auditSnapshot
	auditItems                                                                               []auditItem
	auditPending                                                                             auditSnapshot
	auditMutex                                                                               sync.Mutex
	auditVerify                                                                              bool
	busy                                                                                     bool
	reportPath                                                                               string
	reportMu                                                                                 sync.Mutex
	events                                                                                   = make(chan string, 128)
	uiLines                                                                                  []string
)

type point struct{ X, Y int32 }
type winMsg struct {
	HWnd           uintptr
	Message        uint32
	_              uint32
	WParam, LParam uintptr
	Time           uint32
	Pt             point
	LPrivate       uint32
}
type winClass struct {
	Size, Style                        uint32
	WndProc                            uintptr
	ClsExtra, WndExtra                 int32
	Instance, Icon, Cursor, Background uintptr
	MenuName, ClassName                *uint16
	IconSmall                          uintptr
}

func u(s string) *uint16 { return syscall.StringToUTF16Ptr(s) }
func send(hwnd uintptr, typ uint32, w, l uintptr) uintptr {
	ret, _, _ := procSend.Call(hwnd, uintptr(typ), w, l)
	return ret
}
func set(hwnd uintptr, text string) { procSetText.Call(hwnd, uintptr(unsafe.Pointer(u(text)))) }
func message(s string, flags uintptr) uintptr {
	r, _, _ := procMsgBox.Call(hwndMain, uintptr(unsafe.Pointer(u(s))), uintptr(unsafe.Pointer(u("360 全家桶卸载助手"))), flags)
	return r
}
func create(exStyle uint32, class, title string, style uint32, x, y, w, h int32, id int, parent uintptr) uintptr {
	r, _, _ := procCreate.Call(uintptr(exStyle), uintptr(unsafe.Pointer(u(class))), uintptr(unsafe.Pointer(u(title))), uintptr(style), uintptr(x), uintptr(y), uintptr(w), uintptr(h), parent, uintptr(id), 0, 0)
	if uiFont != 0 {
		send(r, WM_SETFONT, uiFont, 1)
	}
	return r
}
func addLog(s string) {
	line := time.Now().Format("15:04:05") + "  " + s
	uiLines = append(uiLines, line)
	if len(uiLines) > 300 {
		uiLines = uiLines[len(uiLines)-300:]
	}
	if hwndLog != 0 {
		set(hwndLog, strings.Join(uiLines, "\r\n")+"\r\n")
		send(hwndLog, EM_SETSEL, ^uintptr(0), ^uintptr(0))
	}
	saveReport(line)
}
func saveReport(s string) {
	reportMu.Lock()
	defer reportMu.Unlock()
	f, e := os.OpenFile(reportPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e == nil {
		_, _ = fmt.Fprintln(f, s)
		_ = f.Close()
	}
}
func notify(s string) { events <- s; procPost.Call(hwndMain, WM_APP_EVENT, 0, 0) }
func setButtons(enabled bool) {
	b := uintptr(0)
	if enabled {
		b = 1
	}
	for _, h := range []uintptr{btnScan, btnUninstall, btnRemains, btnIsolate, btnRestore, btnVerify} {
		procEnable.Call(h, b)
	}
}
func displayApps() {
	if busy {
		return
	}
	var scanWarnings []string
	apps, scanWarnings = registryScanChecked()
	viewMode = "apps"
	send(hwndList, LB_RESETCONTENT, 0, 0)
	strong, confirm := 0, 0
	for _, a := range apps {
		label := "[需核对]"
		if a.High {
			label = "[已识别]"
			strong++
		} else {
			confirm++
		}
		row := fmt.Sprintf("%s [%s] %s     %s     %s", label, inspectUninstaller(a), a.Name, a.Version, a.Publisher)
		send(hwndList, LB_ADDSTRING, 0, uintptr(unsafe.Pointer(u(row))))
	}
	status := fmt.Sprintf("扫描结果：%d 个候选（%d 个高可信、%d 个需人工核对）。按 Ctrl/Shift 多选。", len(apps), strong, confirm)
	if len(scanWarnings) > 0 {
		status = fmt.Sprintf("扫描不完整（%d 项读取错误），以下结果仅供参考。", len(scanWarnings)) + status
	}
	set(hwndStatus, status)
	for _, warning := range scanWarnings {
		saveReport("  扫描不完整 | " + warning)
	}
	addLog(fmt.Sprintf("扫描安装项：共 %d 个候选（高可信 %d，需核对 %d）", len(apps), strong, confirm))
	for _, a := range apps {
		saveReport(fmt.Sprintf("  发现 | %s | 发布者=%s | 注册表=%s\\%s | %s | 卸载命令=%s", a.Name, a.Publisher, a.RootName, a.KeyName, a.Detection+" | 入口状态="+inspectUninstaller(a), a.Uninstall))
	}
}

type auditItem struct {
	Label, Folder string
	Isolatable    bool
}

func startAudit(verify bool) {
	if busy {
		return
	}
	busy = true
	auditVerify = verify
	setButtons(false)
	set(hwndStatus, "正在采集产品、服务/驱动、进程、计划任务、启动项和文件目录证据……")
	addLog("开始深度诊断（不终止进程、不修改服务及注册表）")
	go func() {
		a := collectAudit()
		auditMutex.Lock()
		auditPending = a
		auditMutex.Unlock()
		notify("__AUDIT_DONE__")
	}()
}
func displayAudit(a auditSnapshot, verify bool) {
	auditCurrent = &a
	viewMode = "audit"
	auditItems = nil
	send(hwndList, LB_RESETCONTENT, 0, 0)
	add := func(label, folder string, can bool) {
		auditItems = append(auditItems, auditItem{Label: label, Folder: folder, Isolatable: can})
		send(hwndList, LB_ADDSTRING, 0, uintptr(unsafe.Pointer(u(label))))
		saveReport("  诊断证据 | " + label)
	}
	for _, x := range a.Products {
		add("[已安装产品] "+x.Name+" | "+x.Publisher, "", false)
	}
	for _, x := range a.Services {
		add("[服务/驱动·仅核对] "+x, "", false)
	}
	for _, x := range a.Processes {
		add("[进程·仅核对] "+x, "", false)
	}
	for _, x := range a.Tasks {
		add("[计划任务·仅核对] "+x, "", false)
	}
	for _, x := range a.Startup {
		add("[启动项·仅核对] "+x, "", false)
	}
	for _, x := range a.Registry {
		add("[注册表·仅核对] "+x, "", false)
	}
	roots := map[string]string{}
	if store, err := isolationStore(); err == nil {
		roots = store.Roots
	} else {
		a.Errors = append(a.Errors, "读取可信用户目录失败："+err.Error())
	}
	for _, x := range a.Folders {
		category, can := safecore.QuarantinableDir(x, roots)
		// Shared ProgramData is still audited and legacy records may be restored,
		// but no new quarantine moves are offered for shared-system directories.
		if strings.HasPrefix(category, "ProgramData:") {
			can = false
		}
		label := "[目录·只读] "
		if can {
			label = "[目录·可恢复隔离候选/含个人数据风险] "
		}
		add(label+x, x, can)
	}
	for _, x := range a.Errors {
		add("[扫描不完整] "+x, "", false)
	}
	if len(auditItems) == 0 {
		add("[当前检查范围内无发现] 不保证零残留", "", false)
	}
	summary := fmt.Sprintf("诊断：产品 %d｜服务/驱动 %d｜进程 %d｜计划任务 %d｜启动项 %d｜目录 %d｜注册表 %d｜异常 %d", len(a.Products), len(a.Services), len(a.Processes), len(a.Tasks), len(a.Startup), len(a.Folders), len(a.Registry), len(a.Errors))
	addLog(summary)
	if verify {
		session, found, err := loadSession()
		if err != nil {
			a.Errors = append(a.Errors, "会话加载失败："+err.Error())
			addLog("会话读取错误：" + err.Error())
		}
		j, jerr := loadJournal()
		count := 0
		if jerr != nil {
			a.Errors = append(a.Errors, "隔离索引读取失败："+jerr.Error())
			addLog("隔离索引读取错误：" + jerr.Error())
		} else {
			count = journalActive(j)
		}
		ev := auditEvidence(a, session, found, count)
		failed, incomplete := workflowEvidence(session, found, ev.RebootObserved)
		ev.WorkflowFailed, ev.WorkflowIncomplete = failed, incomplete
		verdict := safecore.Assess(ev)
		summary = "最终验收【" + verdict.Level + "】" + verdict.Message + "。" + summary
		addLog(summary)
	}
	set(hwndStatus, summary)
}
func beginIsolation() {
	if busy {
		return
	}
	if viewMode != "audit" || auditCurrent == nil {
		message("先点击『深度诊断』，查看可恢复隔离的候选目录。", MB_OK|MB_ICONINFORMATION)
		return
	}
	indices := selectedIndicesN(len(auditItems))
	selected := []string{}
	for _, i := range indices {
		if auditItems[i].Isolatable {
			selected = append(selected, auditItems[i].Folder)
		}
	}
	if len(selected) == 0 {
		message("请在诊断结果中选择标为『可恢复隔离候选』的目录。服务、驱动、安装目录、注册表不会在这里删除。", MB_OK|MB_ICONINFORMATION)
		return
	}
	if message(fmt.Sprintf("准备将 %d 个确切匹配的 360 数据目录移动到隔离区。\n\n注意：其中可能包含浏览器书签、配置或其他个人数据！移动后这些资料将暂时无法供原软件访问。\n\n本操作不是永久删除，可从本工具恢复。只有在确认所有目标软件、相关进程和后台组件消失后才会进行。\n\n继续核验？", len(selected)), MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2) != 6 {
		return
	}
	if message("再次确认：你已备份重要数据，并希望将选中目录隔离？\n若还有任何 360 相关服务/驱动、进程、计划任务、启动项或已安装产品，工具会拒绝隔离。", MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2) != 6 {
		return
	}
	busy = true
	setButtons(false)
	set(hwndStatus, "正在重新采集系统状态并核验隔离条件……")
	go func() {
		a := collectAudit()
		managed, managedError := hasManaged360()
		if managedError != nil || len(a.Errors) > 0 || len(a.Products) > 0 || len(a.Services) > 0 || len(a.Processes) > 0 || len(a.Tasks) > 0 || len(a.Startup) > 0 || managed {
			notify("拒绝隔离：还有目标产品/受管理产品/相关后台组件，或扫描不完整。请先处理并重新诊断。")
			notify("__ISOLATE_DONE__")
			return
		}
		for _, p := range selected {
			r, e := quarantineFolder(p)
			if e != nil {
				notify("隔离失败：" + p + " | " + e.Error())
			} else {
				notify("已恢复性隔离：" + r.Original + " → " + r.Quarantine)
			}
		}
		notify("__ISOLATE_DONE__")
	}()
}
func beginRestore() {
	if busy {
		return
	}
	j, e := loadJournal()
	if e != nil {
		message("隔离索引不可读："+e.Error(), MB_OK|MB_ICONWARNING)
		return
	}
	if journalActive(j) == 0 {
		message("没有需要恢复的隔离记录。", MB_OK|MB_ICONINFORMATION)
		return
	}
	if message(fmt.Sprintf("将尝试恢复 %d 个隔离目录到其原始位置。\n如原位置已有文件，绝不覆盖。确定恢复？", journalActive(j)), MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2) != 6 {
		return
	}
	busy = true
	setButtons(false)
	set(hwndStatus, "正在核对隔离索引并恢复目录……")
	go func() {
		messages, e := restoreAll()
		for _, msg := range messages {
			notify(msg)
		}
		if e != nil {
			notify("恢复操作遇到错误：" + e.Error())
		}
		notify("__RESTORE_DONE__")
	}()
}
func selectedIndices() []int { return selectedIndicesN(len(apps)) }
func selectedIndicesN(max int) []int {
	n := int32(send(hwndList, LB_GETSELCOUNT, 0, 0))
	if n <= 0 || n > 5000 {
		return nil
	}
	idx := make([]int32, n)
	num := int32(send(hwndList, LB_GETSELITEMS, uintptr(n), uintptr(unsafe.Pointer(&idx[0]))))
	if num <= 0 || num > n {
		return nil
	}
	out := make([]int, 0, num)
	for _, j := range idx[:num] {
		if j >= 0 && int(j) < max {
			out = append(out, int(j))
		}
	}
	return out
}
func uninstallSelection() {
	if busy {
		return
	}
	if viewMode != "apps" {
		message("请先点击“扫描已安装产品”，切换到软件列表。", MB_OK|MB_ICONINFORMATION)
		return
	}
	indices := selectedIndices()
	if len(indices) == 0 {
		message("请先在列表中选择准备卸载的产品。\n支持 Ctrl / Shift 多选。", MB_OK|MB_ICONINFORMATION)
		return
	}
	targets := make([]appEntry, 0, len(indices))
	names := []string{}
	for _, i := range indices {
		targets = append(targets, apps[i])
		hint := ""
		if !apps[i].High {
			hint = " [发布者待核对]"
		}
		names = append(names, apps[i].Name+"  ("+apps[i].Publisher+")"+hint)
	}
	prompt := "将依次启动下列软件登记的卸载器：\n\n" + strings.Join(names, "\n") + "\n\n可能出现卸载确认、管理员授权或重启提示。\n请先备份浏览器书签和个人数据。\n不会强制结束保护进程，也不会删除隔离区。\n\n确定继续？"
	if message(prompt, MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2) != 6 {
		return
	}
	if err := saveSession(targets); err != nil {
		message("未能保存重启验收会话，取消卸载："+err.Error(), MB_OK|MB_ICONWARNING)
		return
	}
	busy = true
	setButtons(false)
	set(hwndStatus, "正在运行系统登记的卸载程序。请按照弹出的卸载向导操作。")
	addLog(fmt.Sprintf("开始卸载 %d 个用户选择的项目", len(targets)))
	go func() {
		for idx, a := range targets {
			if err := setTargetState(idx, "running", "正在启动卸载程序"); err != nil {
				notify("无法持久化卸载状态，已停止：" + err.Error())
				break
			}
			notify("正在卸载：" + a.Name)
			result, err := uninstallOne(a)
			if err != nil {
				if e := setTargetState(idx, "failed", err.Error()); e != nil {
					notify("无法记录失败状态：" + e.Error())
				}
				notify("失败 / 需人工处理：" + a.Name + " | " + err.Error())
				notify("已暂停后续卸载：请修复上述故障并重新扫描")
				break
			}
			nextState := "blocked"
			if result.Accepted && result.RegisteredKnown {
				if result.RebootRequired {
					nextState = "reboot_pending"
				} else if !result.StillRegistered {
					nextState = "verified"
				}
			}
			if err := setTargetState(idx, nextState, result.Message); err != nil {
				notify("卸载结果未能持久化，已暂停：" + err.Error())
				break
			}
			notify("完成检查：" + a.Name + " | " + result.Message)
			if !result.Next.MayStartAnother {
				notify("已暂停后续卸载：" + result.Next.Reason)
				break
			}
		}
		notify("__DONE__")
	}()
}
func showReport() {
	if reportPath == "" {
		return
	}
	systemDir, err := windowsSystemDir()
	if err != nil {
		message("无法定位系统记事本："+err.Error(), MB_OK|MB_ICONWARNING)
		return
	}
	if err := exec.Command(filepath.Join(systemDir, "notepad.exe"), reportPath).Start(); err != nil {
		message("无法打开日志："+err.Error(), MB_OK|MB_ICONWARNING)
	}
}
func openApps() {
	systemDir, e := windowsSystemDir()
	if e != nil {
		message("无法定位 Windows 控制面板："+e.Error(), MB_OK|MB_ICONWARNING)
		return
	}
	if err := exec.Command(filepath.Join(systemDir, "control.exe"), "appwiz.cpl").Start(); err != nil {
		message("无法打开 Windows 程序和功能："+err.Error(), MB_OK|MB_ICONWARNING)
	}
}
func onResize(w, h int32) {
	if w < 700 || h < 580 {
		return
	}
	move := func(hnd uintptr, x, y, ww, hh int32) {
		if hnd != 0 {
			procMove.Call(hnd, uintptr(x), uintptr(y), uintptr(ww), uintptr(hh), 1)
		}
	}
	pad := int32(16)
	content := w - pad*2
	move(hwndHeader, pad, 14, content, 30)
	move(hwndDesc, pad, 46, content, 35)
	width := (content - 3*8) / 4
	handles := []uintptr{btnScan, btnUninstall, btnRemains, btnVerify, btnIsolate, btnRestore, btnReport, btnApps}
	for i, hnd := range handles {
		row, col := i/4, i%4
		move(hnd, pad+int32(col)*(width+8), 84+int32(row)*42, width, 34)
	}
	listH := (h - 260) / 2
	if listH < 155 {
		listH = 155
	}
	move(hwndList, pad, 174, content, listH)
	ly := 180 + listH
	move(hwndLogLabel, pad, ly, content, 24)
	move(hwndLog, pad, ly+27, content, h-(ly+27)-42)
	move(hwndStatus, pad, h-33, content, 25)
}
func wndProc(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr {
	switch msg {
	case WM_CREATE:
		hwndMain = hwnd
		fontFace := u("Microsoft YaHei UI")
		uiFont, _, _ = gdi32.NewProc("CreateFontW").Call(^uintptr(18), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(fontFace)))
		hwndHeader = create(0, "STATIC", "360 全家桶卸载助手  ·  v1.0.0", WS_CHILD|WS_VISIBLE, 16, 14, 880, 30, 0, hwnd)
		hwndDesc = create(0, "STATIC", "扫描产品 → 批量卸载 → 深度诊断 → 重启验收 → 安全隔离/恢复。受保护驱动和注册表只诊断不强删。", WS_CHILD|WS_VISIBLE, 16, 48, 880, 30, 0, hwnd)
		btnScan = create(0, "BUTTON", "1. 扫描已安装产品", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 16, 84, 190, 34, BTN_SCAN, hwnd)
		btnUninstall = create(0, "BUTTON", "2. 卸载选中产品", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 214, 84, 190, 34, BTN_UNINSTALL, hwnd)
		btnRemains = create(0, "BUTTON", "3. 深度诊断", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 412, 84, 190, 34, BTN_REMAINS, hwnd)
		btnVerify = create(0, "BUTTON", "4. 重启后验收", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 610, 84, 190, 34, BTN_VERIFY, hwnd)
		btnIsolate = create(0, "BUTTON", "隔离所选残留目录", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 16, 126, 190, 34, BTN_ISOLATE, hwnd)
		btnRestore = create(0, "BUTTON", "恢复已隔离目录", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 214, 126, 190, 34, BTN_RESTORE, hwnd)
		btnReport = create(0, "BUTTON", "查看本地报告", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 412, 126, 190, 34, BTN_REPORT, hwnd)
		btnApps = create(0, "BUTTON", "Windows 卸载界面", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 610, 126, 190, 34, BTN_APPS, hwnd)
		hwndList = create(0x00000200, "LISTBOX", "", WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|LBS_EXTENDEDSEL|WS_TABSTOP, 16, 174, 880, 200, 0, hwnd)
		hwndLogLabel = create(0, "STATIC", "执行记录（保存在本机）：", WS_CHILD|WS_VISIBLE, 16, 382, 880, 24, 0, hwnd)
		hwndLog = create(0x00000200, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY, 16, 410, 880, 190, 0, hwnd)
		hwndStatus = create(0, "STATIC", "就绪。", WS_CHILD|WS_VISIBLE, 16, 607, 880, 26, 0, hwnd)
		addLog("已启动。当前版本提供深度诊断与经核验的目录隔离/恢复，不强删驱动、不停用防护。")
		displayApps()
		return 0
	case WM_COMMAND:
		id := uint16(wparam & 0xffff)
		switch id {
		case BTN_SCAN:
			displayApps()
		case BTN_UNINSTALL:
			uninstallSelection()
		case BTN_REMAINS:
			startAudit(false)
		case BTN_VERIFY:
			startAudit(true)
		case BTN_ISOLATE:
			beginIsolation()
		case BTN_RESTORE:
			beginRestore()
		case BTN_REPORT:
			showReport()
		case BTN_APPS:
			openApps()
		}
		return 0
	case WM_APP_EVENT:
		for {
			select {
			case e := <-events:
				if e == "__AUDIT_DONE__" {
					auditMutex.Lock()
					a := auditPending
					auditMutex.Unlock()
					busy = false
					setButtons(true)
					displayAudit(a, auditVerify)
				} else if e == "__ISOLATE_DONE__" || e == "__RESTORE_DONE__" {
					busy = false
					setButtons(true)
					startAudit(true)
				} else if e == "__DONE__" {
					busy = false
					setButtons(true)
					addLog("本轮卸载流程结束。建议重新扫描、重启 Windows，再检查残留。")
					displayApps()
				} else {
					addLog(e)
				}
			default:
				return 0
			}
		}
	case WM_SIZE:
		onResize(int32(uint16(lparam&0xffff)), int32(uint16((lparam>>16)&0xffff)))
		return 0
	case WM_DESTROY:
		procPostQuit.Call(0)
		return 0
	}
	ret, _, _ := procDef.Call(hwnd, uintptr(msg), wparam, lparam)
	return ret
}
func main() {
	// Serialize destructive workflows across concurrent launches in one login session.
	mutexName := u(`Local\Q360CleanupExclusiveInstance`)
	mutex, _, mutexErr := kernel32.NewProc("CreateMutexW").Call(0, 0, uintptr(unsafe.Pointer(mutexName)))
	if mutex == 0 {
		message("无法创建单实例锁："+mutexErr.Error(), MB_OK|MB_ICONWARNING)
		return
	}
	defer syscall.CloseHandle(syscall.Handle(mutex))
	if mutexErr == syscall.Errno(183) {
		message("Q360 Cleanup 已在运行，请使用已经打开的窗口。", MB_OK|MB_ICONINFORMATION)
		return
	}
	reportPath = reportFile()
	if reportPath == "" {
		message("无法建立可信的本地报告目录；请检查当前 Windows 用户配置文件。", MB_OK|MB_ICONWARNING)
		return
	}
	saveReport("360 全家桶卸载助手 v1.0.0  |  " + time.Now().Format(time.RFC3339))
	instance, _, _ := kernel32.NewProc("GetModuleHandleW").Call(0)
	className := u("Q360CleanupNativeWin32")
	wc := winClass{Size: uint32(unsafe.Sizeof(winClass{})), WndProc: syscall.NewCallback(wndProc), Instance: instance, Background: 6, ClassName: className}
	wc.Cursor, _, _ = user32.NewProc("LoadCursorW").Call(0, 32512)
	if r, _, err := procRegClass.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		fmt.Fprintln(os.Stderr, "RegisterClassExW:", err)
		return
	}
	hwnd, _, err := procCreate.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(u("360 全家桶卸载助手 - Q360 Cleanup"))), uintptr(WS_OVERLAPPEDWINDOW|WS_VISIBLE), 100, 80, 940, 695, 0, 0, instance, 0)
	if hwnd == 0 {
		fmt.Fprintln(os.Stderr, "CreateWindowExW:", err)
		return
	}
	procShow.Call(hwnd, 1)
	procUpdate.Call(hwnd)
	var m winMsg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslate.Call(uintptr(unsafe.Pointer(&m)))
		procDispatch.Call(uintptr(unsafe.Pointer(&m)))
	}
}
