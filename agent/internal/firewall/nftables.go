package firewall

import (
	"fmt"
	"log"
	"net"
)

// NFTablesManager manages nftables rules for JZap blocklist and rate-limiting.
type NFTablesManager struct {
	// blocklist holds the current set of blocked IPs for bookkeeping.
	blocklist map[string]struct{}
}

// New creates and returns a new NFTablesManager.
// In a production implementation this would open a netlink connection to nftables.
func New() (*NFTablesManager, error) {
	log.Println("nftables: initializing firewall manager")
	// TODO: open netlink connection to nftables and create the jzap table/chain/set.
	return &NFTablesManager{
		blocklist: make(map[string]struct{}),
	}, nil
}

// AddBlocklistEntry adds a single IP to the JZap blocklist set.
func (m *NFTablesManager) AddBlocklistEntry(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("nftables: invalid IP address %q", ip)
	}
	log.Printf("nftables: adding blocklist entry %s", ip)
	m.blocklist[ip] = struct{}{}
	// TODO: implement nftables rule add via netlink.
	return nil
}

// RemoveBlocklistEntry removes a single IP from the JZap blocklist set.
func (m *NFTablesManager) RemoveBlocklistEntry(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("nftables: invalid IP address %q", ip)
	}
	log.Printf("nftables: removing blocklist entry %s", ip)
	delete(m.blocklist, ip)
	// TODO: implement nftables rule removal via netlink.
	return nil
}

// SyncBlocklist replaces the entire JZap blocklist set with the given entries.
func (m *NFTablesManager) SyncBlocklist(entries []string) error {
	log.Printf("nftables: syncing blocklist with %d entries", len(entries))

	// Validate all entries first.
	for _, ip := range entries {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("nftables: invalid IP address %q in blocklist", ip)
		}
	}

	// Replace the in-memory set.
	newSet := make(map[string]struct{}, len(entries))
	for _, ip := range entries {
		newSet[ip] = struct{}{}
	}
	m.blocklist = newSet

	// TODO: flush the nftables set and re-populate it atomically.
	return nil
}

// AddRateLimit adds a per-IP packets-per-second rate limit rule.
func (m *NFTablesManager) AddRateLimit(ip string, ppsLimit uint64) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("nftables: invalid IP address %q", ip)
	}
	log.Printf("nftables: adding rate limit for %s: %d pps", ip, ppsLimit)
	// TODO: implement nftables rate-limit rule via netlink.
	return nil
}

// Flush removes all JZap-managed nftables rules, chains, and sets.
func (m *NFTablesManager) Flush() error {
	log.Println("nftables: flushing all JZap rules")
	m.blocklist = make(map[string]struct{})
	// TODO: delete the jzap table (which cascades chains and sets).
	return nil
}

// Close releases any resources held by the firewall manager.
func (m *NFTablesManager) Close() error {
	log.Println("nftables: closing firewall manager")
	// TODO: close netlink connection.
	return nil
}
