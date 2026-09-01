package rz

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// AuditStore is an append-only structured JSON audit log (JSONL).
// Every entry from every actor/decision lands here.
//
// Tamper-evidence: Append chains each entry to the previous one by computing
// prevHash + hash BEFORE writing, so the log is a hash chain.
type AuditStore struct {
	mu sync.Mutex
	f  string
}

// NewAuditStore creates (or opens) the JSONL audit log at logFile.
// An empty logFile defaults to data/audit.log.jsonl under the working dir.
func NewAuditStore(logFile string) (*AuditStore, error) {
	if logFile == "" {
		logFile = filepath.Join("data", "audit.log.jsonl")
	}
	if err := os.MkdirAll(filepath.Dir(logFile), 0o755); err != nil {
		return nil, err
	}
	return &AuditStore{f: logFile}, nil
}

func (s *AuditStore) Path() string { return s.f }

// Append hashes and writes one entry.
func (s *AuditStore) Append(e AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prevHash, err := readLastHash(s.f)
	if err != nil {
		return err
	}
	if prevHash == "" {
		prevHash = GenesisHash
	}
	entry := e
	entry.PrevHash = prevHash
	entry.Hash = ComputeHash(prevHash, &e)
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.f, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// All returns every stored entry in order.
func (s *AuditStore) All() ([]AuditEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return readAllEntries(s.f)
}

// Clear removes the log file.
func (s *AuditStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.f)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ReadAuditFile reads ALL entries from a JSONL audit file (for verification
// CLIs that don't hold a store handle). Returns an error if the file is absent.
func ReadAuditFile(file string) ([]AuditEntry, error) {
	entries, err := readAllEntries(file)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 && fileExists(file) == false {
		return nil, os.ErrNotExist
	}
	return entries, nil
}

func fileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// readLastHash reads just the last entry's hash (the chain tail).
func readLastHash(file string) (string, error) {
	entries, err := readAllEntries(file)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", nil
	}
	return entries[len(entries)-1].Hash, nil
}

func readAllEntries(file string) ([]AuditEntry, error) {
	f, err := os.Open(file)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditEntry{}, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []AuditEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
