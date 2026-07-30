// allow-claude-code: implements the login slot guard from the delegated
// brief; it is deliberately small and filesystem-only so credroute still
// routes credentials without becoming a vault backend.
package slotsnap

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

// Snapshot is a restorable copy of a credential slot.
type Snapshot struct {
	Slot   string
	Target string
	Path   string
	sum    string
}

// Lock is an exclusive, non-blocking lock for one slot.
type Lock struct {
	file *os.File
}

func AcquireLock(stateDir, slot string) (*Lock, error) {
	if slot == "" {
		return nil, errors.New("slotsnap: slot is required")
	}
	dir := filepath.Join(stateDir, "login-locks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("slotsnap: create lock dir: %w", err)
	}
	name := hash(slot) + ".lock"
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("slotsnap: open lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("slotsnap: acquire lock: %w", err)
	}
	return &Lock{file: f}, nil
}

func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

var ErrLocked = errors.New("slotsnap: slot login already in progress")

var renamePath = os.Rename

func Take(stateDir, slot string) (*Snapshot, error) {
	target, err := filepath.EvalSymlinks(slot)
	if err != nil {
		return nil, fmt.Errorf("slotsnap: resolve slot symlinks: %w", err)
	}
	info, err := os.Lstat(target)
	if err != nil {
		return nil, fmt.Errorf("slotsnap: stat slot: %w", err)
	}
	dir := filepath.Join(stateDir, "login-snapshots")
	_ = Prune(dir, 20, 7*24*time.Hour)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("slotsnap: create snapshot dir: %w", err)
	}
	snapDir := filepath.Join(dir, hash(slot)+"-"+nonce())
	if err := os.Mkdir(snapDir, 0o700); err != nil {
		return nil, fmt.Errorf("slotsnap: create snapshot: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(snapDir)
		}
	}()
	dst := filepath.Join(snapDir, "slot")
	if err := copyPath(target, dst, info); err != nil {
		return nil, err
	}
	sum, err := digestPath(dst)
	if err != nil {
		return nil, err
	}
	ok = true
	return &Snapshot{Slot: slot, Target: target, Path: dst, sum: sum}, nil
}

func (s *Snapshot) Restore() error {
	if s == nil {
		return errors.New("slotsnap: no snapshot")
	}
	target := s.restoreTarget()
	parent := filepath.Dir(target)
	tmp := filepath.Join(parent, "."+filepath.Base(target)+".credroute-restore-"+nonce())
	swapped := false
	defer func() {
		if !swapped {
			_ = os.RemoveAll(tmp)
		}
	}()
	info, err := os.Lstat(s.Path)
	if err != nil {
		return fmt.Errorf("slotsnap: stat snapshot: %w", err)
	}
	if err := copyPath(s.Path, tmp, info); err != nil {
		return err
	}
	backup := filepath.Join(parent, "."+filepath.Base(target)+".credroute-replaced-"+nonce())
	if err := renamePath(target, backup); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("slotsnap: move current slot aside: %w", err)
		}
		if err := renamePath(tmp, target); err != nil {
			return fmt.Errorf("slotsnap: restore missing slot: %w", err)
		}
		swapped = true
		return nil
	}
	if err := renamePath(tmp, target); err != nil {
		_ = renamePath(backup, target)
		return fmt.Errorf("slotsnap: restore slot: %w", err)
	}
	swapped = true
	_ = os.RemoveAll(backup)
	return nil
}

func (s *Snapshot) ConfirmRestored() error {
	got, err := s.CurrentDigest()
	if err != nil {
		return err
	}
	if got != s.sum {
		return errors.New("slotsnap: restored slot differs from snapshot")
	}
	return nil
}

func (s *Snapshot) InitialDigest() string {
	if s == nil {
		return ""
	}
	return s.sum
}

func (s *Snapshot) CurrentDigest() (string, error) {
	if s == nil {
		return "", errors.New("slotsnap: no snapshot")
	}
	return digestPath(s.restoreTarget())
}

func (s *Snapshot) Remove() error {
	if s == nil || s.Path == "" {
		return nil
	}
	return os.RemoveAll(filepath.Dir(s.Path))
}

func (s *Snapshot) restoreTarget() string {
	if s.Target != "" {
		return s.Target
	}
	return s.Slot
}

func Prune(dir string, keep int, maxAge time.Duration) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("slotsnap: read snapshot dir: %w", err)
	}
	type snapDir struct {
		name    string
		modTime time.Time
	}
	var dirs []snapDir
	cutoff := time.Now().Add(-maxAge)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if maxAge > 0 && info.ModTime().Before(cutoff) {
			_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
			continue
		}
		dirs = append(dirs, snapDir{name: entry.Name(), modTime: info.ModTime()})
	}
	sort.Slice(dirs, func(i, j int) bool {
		return dirs[i].modTime.After(dirs[j].modTime)
	})
	for i := keep; keep >= 0 && i < len(dirs); i++ {
		_ = os.RemoveAll(filepath.Join(dir, dirs[i].name))
	}
	return nil
}

func copyPath(src, dst string, info fs.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(src)
		if err != nil {
			return fmt.Errorf("slotsnap: resolve symlink %s: %w", src, err)
		}
		return fmt.Errorf("slotsnap: symlink inside slot is unsafe: %s -> %s", src, target)
	}
	if info.IsDir() {
		return copyDir(src, dst, info.Mode().Perm())
	}
	return copyFile(src, dst, info.Mode().Perm())
}

func copyDir(src, dst string, perm os.FileMode) error {
	if err := os.MkdirAll(dst, perm); err != nil {
		return fmt.Errorf("slotsnap: create dir copy: %w", err)
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == src {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return copyPath(path, filepath.Join(dst, rel), info)
	})
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("slotsnap: open source: %w", err)
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("slotsnap: create parent: %w", err)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return fmt.Errorf("slotsnap: create copy: %w", err)
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(dst)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("slotsnap: copy file: %w", err)
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("slotsnap: sync copy: %w", err)
	}
	ok = true
	return nil
}

func digestPath(path string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(path, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(path, p)
		if err != nil {
			return err
		}
		h.Write([]byte(rel))
		info, err := d.Info()
		if err != nil {
			return err
		}
		h.Write([]byte(info.Mode().String()))
		if d.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			h.Write([]byte(target))
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(h, f)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("slotsnap: digest slot: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func nonce() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "fallback"
	}
	return hex.EncodeToString(b[:])
}
