package safecore

// UninstallStep expresses the safe decision after each registered uninstaller.
// A process exit by itself is never evidence that its asynchronous descendants
// or self-protected services have finished removing the product.
type UninstallStep struct {
	ExitAccepted    bool
	RegisteredKnown bool
	StillRegistered bool
	RebootRequired  bool
}

type NextStep struct {
	MayStartAnother bool
	Reason          string
}

func DecideBatchStep(s UninstallStep) NextStep {
	if !s.ExitAccepted {
		return NextStep{Reason: "卸载程序失败或被取消，已暂停批量操作以避免叠加故障"}
	}
	if !s.RegisteredKnown {
		return NextStep{Reason: "安装登记复查失败，状态未知；已暂停后续卸载"}
	}
	if s.StillRegistered {
		return NextStep{Reason: "产品仍有安装登记，卸载器可能继续在后台运行；已暂停后续卸载"}
	}
	if s.RebootRequired {
		return NextStep{Reason: "卸载器要求重启，后续卸载必须等待重启与复查"}
	}
	return NextStep{MayStartAnother: true, Reason: "该产品卸载登记已消失，可继续下一个产品（最终仍须整体验收）"}
}
