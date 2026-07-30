package cache

import (
	"crypto/tls"
	"time"
)

// CertificateCacheEntry is a cached TLS certificate bundle and its storage time.
//
// Fields:
//   - Certificate (*tls.Certificate): The cached certificate bundle (leaf plus CA chain).
//   - CreatedAt (time.Time): When the entry was stored; the authority compares it against
//     its maximum cache age, and [InMemory] uses it for oldest-first eviction.
type CertificateCacheEntry struct {
	Certificate *tls.Certificate
	CreatedAt   time.Time
}

// CertificateCache stores dynamically generated certificates keyed by normalized hostname.
//
// Implementations must be safe for concurrent use. The authority never calls Set
// concurrently for the same host (in-flight generation is deduplicated), but concurrent
// Get and Set calls for different hosts are expected.
//
// The cache is pure storage: the authority decides whether a returned entry may be
// served (maximum age and leaf expiry), so implementations cannot get certificate
// validity wrong. Get runs on every TLS handshake and must be cheap.
//
// Methods:
//   - Get returns the entry stored for host, or found = false when none is stored.
//   - Set stores entry for host, replacing any existing entry; implementations may
//     evict entries at their own discretion.
type CertificateCache interface {
	Get(host string) (entry *CertificateCacheEntry, found bool)
	Set(host string, entry *CertificateCacheEntry)
}
