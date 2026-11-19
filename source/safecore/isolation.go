package safecore

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type IsolationRecord struct {
	ID         string    `json:"id"`
	Original   string    `json:"original"`
	Quarantine string    `json:"quarantine"`
	State      string    `json:"state"` // preparing, isolated, restoring, restored
	Category   string    `json:"category"`
	At         time.Time `json:"at"`
}
type IsolationJournal struct {
	Version int               `json:"version"`
	Items   []IsolationRecord `json:"items"`
}

func (j IsolationJournal) Active() int {
	n := 0
	for _, r := range j.Items {
		if r.State != "restored" {
			n++
		}
	}
	return n
}

var isolationID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)

type IsolationStore struct {
	DataDir string
	Roots   map[string]string
}

func (s IsolationStore) journalPath() string { return filepath.Join(s.DataDir, "isolation.json") }

// SaveJSONAtomic uses a same-directory temporary file + rename. A journal is
// written before each filesystem move, making crashes reconstructable.
func SaveJSONAtomic(path string, val any) error {
	data, e := json.MarshalIndent(val, "", "  ")
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	temp, e := os.CreateTemp(filepath.Dir(path), ".pending-*.json")
	if e != nil {
		return e
	}
	defer os.Remove(temp.Name())
	if e = temp.Chmod(0600); e != nil {
		temp.Close()
		return e
	}
	if _, e = temp.Write(data); e != nil {
		temp.Close()
		return e
	}
	if e = temp.Sync(); e != nil {
		temp.Close()
		return e
	}
	if e = temp.Close(); e != nil {
		return e
	}
	return os.Rename(temp.Name(), path)
}
func (s IsolationStore) Load() (IsolationJournal, error) {
	if !filepath.IsAbs(s.DataDir) {
		return IsolationJournal{}, errors.New("隔离数据目录非绝对路径")
	}
	f, e := os.Open(s.journalPath())
	if os.IsNotExist(e) {
		return IsolationJournal{Version: 1}, nil
	}
	if e != nil {
		return IsolationJournal{}, e
	}
	defer f.Close()
	stat, e := f.Stat()
	if e != nil {
		return IsolationJournal{}, e
	}
	if stat.Size() > 10*1024*1024 {
		return IsolationJournal{}, errors.New("隔离清单异常过大")
	}
	var j IsolationJournal
	decoder := json.NewDecoder(f)
	if e = decoder.Decode(&j); e != nil {
		return j, e
	}
	var extra any
	if e = decoder.Decode(&extra); e != io.EOF {
		if e == nil {
			return j, errors.New("隔离清单包含多个 JSON 对象")
		}
		return j, fmt.Errorf("隔离清单存在尾随非法数据：%w", e)
	}
	if j.Version != 1 {
		return j, errors.New("隔离清单版本不兼容")
	}
	if err := s.validateJournal(j); err != nil {
		return j, err
	}
	return j, nil
}

// validateJournal treats the disk file as untrusted. A forged record cannot
// redirect restoration outside this application's quarantine and whitelist.
func (s IsolationStore) validateJournal(j IsolationJournal) error {
	if len(j.Items) > 10000 {
		return errors.New("隔离清单项目异常过多")
	}
	ids := make(map[string]bool, len(j.Items))
	activeSources := make(map[string]bool, len(j.Items))
	for _, r := range j.Items {
		if !isolationID.MatchString(r.ID) || ids[r.ID] {
			return errors.New("隔离清单含非法或重复 ID")
		}
		ids[r.ID] = true
		expected := filepath.Join(s.DataDir, "Quarantine", r.ID)
		if !filepath.IsAbs(r.Quarantine) || !strings.EqualFold(filepath.Clean(r.Quarantine), filepath.Clean(expected)) {
			return errors.New("隔离清单目标目录不属于本工具")
		}
		category, allowed := QuarantinableDir(r.Original, s.Roots)
		if !allowed || (r.Category != "" && r.Category != category) {
			return errors.New("隔离清单源路径不属于已批准目录")
		}
		switch r.State {
		case "preparing", "isolated", "restoring", "restored":
		default:
			return errors.New("隔离清单含未知状态")
		}
		if r.State != "restored" {
			name := strings.ToLower(filepath.Clean(r.Original))
			if activeSources[name] {
				return errors.New("隔离清单含重复未恢复源目录")
			}
			activeSources[name] = true
		}
	}
	return nil
}
func (s IsolationStore) Save(j IsolationJournal) error { return SaveJSONAtomic(s.journalPath(), j) }
func fileStatus(path string) (exists bool, err error) {
	_, e := os.Lstat(path)
	if e == nil {
		return true, nil
	}
	if os.IsNotExist(e) {
		return false, nil
	}
	return false, e
}

// Reconcile transitional entries after an interrupted move; unknown states
// remain unresolved and always fail closed.
func (j *IsolationJournal) Reconcile() bool {
	changed := false
	for i := range j.Items {
		r := &j.Items[i]
		if r.State != "preparing" && r.State != "restoring" {
			continue
		}
		source, sourceErr := fileStatus(r.Original)
		destination, destErr := fileStatus(r.Quarantine)
		if sourceErr != nil || destErr != nil {
			continue
		}
		if !source && destination {
			r.State = "isolated"
			changed = true
		}
		if source && !destination {
			r.State = "restored"
			changed = true
		}
	}
	return changed
}
func (s IsolationStore) LoadReconciled() (IsolationJournal, error) {
	j, e := s.Load()
	if e != nil {
		return j, e
	}
	if j.Reconcile() {
		if e = s.Save(j); e != nil {
			return j, e
		}
	}
	return j, nil
}
func (s IsolationStore) safeSource(path string) (string, error) {
	label, ok := QuarantinableDir(path, s.Roots)
	if !ok {
		return "", fmt.Errorf("路径不在准确允许名单：%s", path)
	}
	absolute := filepath.Clean(path)
	resolved, e := filepath.EvalSymlinks(absolute)
	if e != nil {
		return "", e
	}
	if !strings.EqualFold(filepath.Clean(resolved), absolute) {
		return "", errors.New("目标路径穿过符号链接或目录联接点")
	}
	info, e := os.Lstat(absolute)
	if e != nil {
		return "", e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("目标不是普通目录或是链接")
	}
	return label, nil
}
func (s IsolationStore) Quarantine(path string) (IsolationRecord, error) {
	label, e := s.safeSource(path)
	if e != nil {
		return IsolationRecord{}, e
	}
	// Shared ProgramData directories can contain shared services or data from
	// other user sessions. This release only permits per-user quarantine.
	if strings.HasPrefix(label, "ProgramData:") {
		return IsolationRecord{}, errors.New("共享 ProgramData 目录只供诊断，不能隔离")
	}
	j, e := s.LoadReconciled()
	if e != nil {
		return IsolationRecord{}, e
	}
	for _, r := range j.Items {
		if strings.EqualFold(filepath.Clean(r.Original), filepath.Clean(path)) && r.State != "restored" {
			return IsolationRecord{}, errors.New("目录已存在未恢复的隔离记录")
		}
	}
	qDir := filepath.Join(s.DataDir, "Quarantine")
	if e = os.MkdirAll(qDir, 0700); e != nil {
		return IsolationRecord{}, e
	}
	// Keep the destination directory itself from being a link to a different tree.
	resolved, e := filepath.EvalSymlinks(qDir)
	if e != nil {
		return IsolationRecord{}, e
	}
	if !strings.EqualFold(filepath.Clean(resolved), filepath.Clean(qDir)) {
		return IsolationRecord{}, errors.New("隔离库目录路径存在链接，拒绝移动")
	}
	now := time.Now()
	entropy := make([]byte, 12)
	if _, e := rand.Read(entropy); e != nil {
		return IsolationRecord{}, fmt.Errorf("无法取得隔离记录随机标识：%w", e)
	}
	id := now.Format("20060102T150405") + "_" + hex.EncodeToString(entropy)
	dest := filepath.Join(qDir, id)
	exists, e := fileStatus(dest)
	if e != nil {
		return IsolationRecord{}, e
	}
	if exists {
		return IsolationRecord{}, errors.New("隔离目标已存在")
	}
	r := IsolationRecord{ID: id, Original: filepath.Clean(path), Quarantine: dest, State: "preparing", Category: label, At: now}
	j.Items = append(j.Items, r)
	if e = s.Save(j); e != nil {
		return r, e
	}
	// Atomic rename on the same volume; deliberately no cross-volume copy/delete.
	if e = os.Rename(path, dest); e != nil {
		return r, fmt.Errorf("移动失败（跨卷或文件被占用）：%w", e)
	}
	j.Items[len(j.Items)-1].State = "isolated"
	if e = s.Save(j); e != nil {
		return r, fmt.Errorf("目录已移动，写回索引失败；需恢复工具重建记录：%w", e)
	}
	r.State = "isolated"
	return r, nil
}
func (s IsolationStore) RestoreAll() ([]string, error) {
	j, e := s.LoadReconciled()
	if e != nil {
		return nil, e
	}
	messages := []string{}
	for i := len(j.Items) - 1; i >= 0; i-- {
		r := &j.Items[i]
		if r.State == "restored" {
			continue
		}
		if r.State != "isolated" {
			messages = append(messages, "无法确定隔离状态，跳过 "+r.Original)
			continue
		}
		if !isolationID.MatchString(r.ID) || !strings.EqualFold(filepath.Clean(r.Quarantine), filepath.Clean(filepath.Join(s.DataDir, "Quarantine", r.ID))) {
			messages = append(messages, "隔离清单目标路径不合法，拒绝恢复 "+r.ID)
			continue
		}
		resolved, e := filepath.EvalSymlinks(filepath.Dir(r.Quarantine))
		if e != nil || !strings.EqualFold(filepath.Clean(resolved), filepath.Clean(filepath.Dir(r.Quarantine))) {
			messages = append(messages, "隔离目录存在链接或不可访问，拒绝恢复 "+r.ID)
			continue
		}
		info, e := os.Lstat(r.Quarantine)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			messages = append(messages, "隔离数据不是普通目录，拒绝恢复 "+r.ID)
			continue
		}
		if _, ok := QuarantinableDir(r.Original, s.Roots); !ok {
			messages = append(messages, "原位置不在允许名单，跳过 "+r.Original)
			continue
		}
		existing, e := fileStatus(r.Original)
		if e != nil || existing {
			messages = append(messages, "原位置不可用或已被占用，拒绝覆盖 "+r.Original)
			continue
		}
		if _, e = os.Lstat(r.Quarantine); e != nil {
			messages = append(messages, "隔离数据丢失："+r.Quarantine)
			continue
		}
		parent := filepath.Dir(r.Original)
		// Revalidate the parent after loading the journal; avoid restoring into
		// an untrusted reparse-point redirect at the original location.
		rp, pe := filepath.EvalSymlinks(parent)
		if pe != nil || !strings.EqualFold(filepath.Clean(rp), filepath.Clean(parent)) {
			messages = append(messages, "原目录上级路径存在重定向/不可读取，拒绝恢复 "+r.Original)
			continue
		}
		if e = os.MkdirAll(parent, 0700); e != nil {
			messages = append(messages, e.Error())
			continue
		}
		r.State = "restoring"
		if e = s.Save(j); e != nil {
			return messages, e
		}
		if e = os.Rename(r.Quarantine, r.Original); e != nil {
			r.State = "isolated"
			_ = s.Save(j)
			messages = append(messages, "恢复失败："+e.Error())
			continue
		}
		r.State = "restored"
		if e = s.Save(j); e != nil {
			return messages, e
		}
		messages = append(messages, "已恢复："+r.Original)
	}
	return messages, nil
}
