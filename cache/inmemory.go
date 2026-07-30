package cache

import (
	"fmt"
	"sync"
	"time"
)

// InMemory is a [CertificateCache] backed by an in-process map.
//
// It holds at most maxSize entries; when full and a new host is stored, the entry
// with the earliest CreatedAt is evicted (oldest-first). Entries are never expired
// eagerly: freshness is the authority's concern, and a stale entry is simply
// overwritten when the authority re-issues the certificate.
//
// InMemory is safe for concurrent use by multiple goroutines.
//
// Fields:
//   - mutex (sync.RWMutex): Guards entries.
//   - entries (map[string]*CertificateCacheEntry): The stored entries, keyed by normalized hostname.
//   - maxSize (int): The maximum number of entries held before eviction.
type InMemory struct {
	mutex   sync.RWMutex
	entries map[string]*CertificateCacheEntry
	maxSize int
}

// Compile-time check that InMemory satisfies the CertificateCache interface.
var _ CertificateCache = (*InMemory)(nil)

// NewInMemory creates an in-memory certificate cache holding at most maxSize entries.
//
// Parameters:
//   - maxSize (int): The maximum number of entries held before oldest-first eviction;
//     must be positive (e.g., 1024).
//
// Returns:
//   - cache (*InMemory): The initialized in-memory cache.
//   - err (error): An error if maxSize is not positive; otherwise, nil.
func NewInMemory(maxSize int) (cache *InMemory, err error) {
	if maxSize <= 0 {
		err = fmt.Errorf("invalid input, cache max size must be positive, got %d", maxSize)

		return nil, err
	}

	cache = &InMemory{
		entries: make(map[string]*CertificateCacheEntry),
		maxSize: maxSize,
	}

	return cache, nil
}

// Get returns the entry stored for the given host.
//
// Parameters:
//   - host (string): The normalized hostname to look up.
//
// Returns:
//   - entry (*CertificateCacheEntry): The stored entry, or nil when none is stored.
//   - found (bool): True when an entry is stored for host; otherwise, false.
func (c *InMemory) Get(host string) (entry *CertificateCacheEntry, found bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, found = c.entries[host]

	return entry, found
}

// Set stores an entry for the given host, replacing any existing entry.
//
// When the cache is full and the host is new, the entry with the earliest
// CreatedAt is evicted first. Storing an existing host never triggers eviction.
//
// Parameters:
//   - host (string): The normalized hostname to store the entry under.
//   - entry (*CertificateCacheEntry): The entry to store.
func (c *InMemory) Set(host string, entry *CertificateCacheEntry) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, exists := c.entries[host]; !exists && len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[host] = entry
}

// evictOldest removes the entry with the earliest CreatedAt from the cache.
//
// It is called when the cache reaches its maximum size (maxSize) to make room
// for a new entry, and is a safe no-op on an empty cache.
func (c *InMemory) evictOldest() {
	var oldestHost string

	var oldestTime time.Time

	for host, entry := range c.entries {
		if oldestTime.IsZero() || entry.CreatedAt.Before(oldestTime) {
			oldestTime = entry.CreatedAt
			oldestHost = host
		}
	}

	if oldestHost != "" {
		delete(c.entries, oldestHost)
	}
}
