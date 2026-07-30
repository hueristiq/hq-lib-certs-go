// Package cache defines the certificate storage port used by the
// CertificateAuthority of the certs package, and provides ready-made
// implementations of it.
//
// A CertificateAuthority has no cache by default: it regenerates a
// certificate on every request. Passing a [CertificateCache] to the
// authority's WithCache option enables reuse of the certificates it issues
// dynamically. [InMemory] is the ready-made implementation; custom
// implementations only need to store and return entries, because the
// authority itself decides whether a returned entry may still be served.
package cache
