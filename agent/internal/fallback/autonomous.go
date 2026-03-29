package fallback

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"

	"github.com/jzap/agent/internal/firewall"
)

// Manager handles autonomous fallback mode. When the control plane is
// unreachable the agent loads the last-known blocklist from disk and
// continues enforcing rules independently.
type Manager struct {
	fw           *firewall.NFTablesManager
	fallbackPath string
	inFallback   atomic.Bool
}

// New creates a new fallback Manager.
func New(fw *firewall.NFTablesManager, fallbackPath string) *Manager {
	return &Manager{
		fw:           fw,
		fallbackPath: fallbackPath,
	}
}

// EnterFallbackMode loads the last-known blocklist from disk and applies it
// via the firewall manager. The agent continues to enforce these rules until
// the control plane becomes reachable again.
func (m *Manager) EnterFallbackMode() error {
	if m.inFallback.Load() {
		log.Println("fallback: already in fallback mode")
		return nil
	}

	log.Println("fallback: entering autonomous fallback mode")

	entries, err := LoadFallbackBlocklist(m.fallbackPath)
	if err != nil {
		return fmt.Errorf("fallback: loading blocklist: %w", err)
	}

	if err := m.fw.SyncBlocklist(entries); err != nil {
		return fmt.Errorf("fallback: applying blocklist: %w", err)
	}

	m.inFallback.Store(true)
	log.Printf("fallback: applied %d entries from fallback blocklist", len(entries))
	return nil
}

// ExitFallbackMode signals that the control plane is reachable again and
// normal sync mode should resume.
func (m *Manager) ExitFallbackMode() error {
	if !m.inFallback.Load() {
		return nil
	}

	log.Println("fallback: exiting autonomous fallback mode, resuming normal sync")
	m.inFallback.Store(false)
	return nil
}

// IsInFallback returns true if the agent is currently operating in autonomous
// fallback mode.
func (m *Manager) IsInFallback() bool {
	return m.inFallback.Load()
}

// LoadFallbackBlocklist reads a saved blocklist file from disk. The file is
// expected to contain one IP address per line. Empty lines and lines starting
// with '#' are ignored.
func LoadFallbackBlocklist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening fallback blocklist %s: %w", path, err)
	}
	defer f.Close()

	var entries []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading fallback blocklist: %w", err)
	}

	return entries, nil
}
