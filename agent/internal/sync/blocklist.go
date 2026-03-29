package sync

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jzap/agent/internal/firewall"
)

// BlocklistSyncer periodically fetches the blocklist from the control plane
// and applies it to the local firewall.
type BlocklistSyncer struct {
	controlPlaneURL string
	httpClient      *http.Client
	interval        time.Duration
	fw              *firewall.NFTablesManager
	fallbackPath    string
}

// New creates a new BlocklistSyncer.
func New(url string, interval time.Duration, fw *firewall.NFTablesManager) *BlocklistSyncer {
	return &BlocklistSyncer{
		controlPlaneURL: strings.TrimRight(url, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		interval: interval,
		fw:       fw,
	}
}

// SetFallbackPath sets the path where fallback copies of the blocklist are saved.
func (s *BlocklistSyncer) SetFallbackPath(path string) {
	s.fallbackPath = path
}

// Start runs the sync loop. It fetches the blocklist on startup and then at
// every tick interval. It returns an error only if the initial fetch fails.
// Subsequent failures are logged but do not stop the loop.
func (s *BlocklistSyncer) Start(ctx context.Context) error {
	log.Printf("blocklist-sync: starting sync loop (interval=%s)", s.interval)

	// Perform an initial sync immediately.
	if err := s.syncOnce(ctx); err != nil {
		return fmt.Errorf("blocklist-sync: initial sync failed: %w", err)
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("blocklist-sync: stopping sync loop")
			return nil
		case <-ticker.C:
			if err := s.syncOnce(ctx); err != nil {
				log.Printf("blocklist-sync: sync error: %v", err)
			}
		}
	}
}

// syncOnce performs a single fetch-and-apply cycle.
func (s *BlocklistSyncer) syncOnce(ctx context.Context) error {
	entries, err := s.fetchBlocklist(ctx)
	if err != nil {
		return err
	}

	if err := s.fw.SyncBlocklist(entries); err != nil {
		return fmt.Errorf("applying blocklist: %w", err)
	}

	// Save a fallback copy if a path is configured.
	if s.fallbackPath != "" {
		if err := SaveFallbackCopy(entries, s.fallbackPath); err != nil {
			log.Printf("blocklist-sync: failed to save fallback copy: %v", err)
		}
	}

	log.Printf("blocklist-sync: synced %d entries", len(entries))
	return nil
}

// blocklistResponse is the expected JSON response from the control plane.
type blocklistResponse struct {
	Entries []string `json:"entries"`
}

// fetchBlocklist makes an HTTP GET request to the control plane blocklist endpoint.
func (s *BlocklistSyncer) fetchBlocklist(ctx context.Context) ([]string, error) {
	url := s.controlPlaneURL + "/api/v1/blocklist"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "jzap-agent/1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching blocklist from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("blocklist endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var result blocklistResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding blocklist response: %w", err)
	}

	return result.Entries, nil
}

// SaveFallbackCopy writes the blocklist entries to a file on disk so the agent
// can operate in autonomous fallback mode if the control plane is unreachable.
func SaveFallbackCopy(entries []string, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating fallback file %s: %w", path, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, entry := range entries {
		if _, err := fmt.Fprintln(w, entry); err != nil {
			return fmt.Errorf("writing to fallback file: %w", err)
		}
	}
	return w.Flush()
}
