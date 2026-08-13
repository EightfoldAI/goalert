package cloudwatch

import (
	"context"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	// maxCachedCerts bounds the cache. The cert URL path is attacker-supplied,
	// so without a bound `https://sns.<region>.amazonaws.com/<random>.pem` mints
	// unlimited entries. SNS's real working set is one or two certs.
	maxCachedCerts = 32

	// maxCachedCertFailures bounds the negative cache, for the same reason as
	// maxCachedCerts: its keys are attacker-supplied. Larger than the positive
	// bound because failures are the higher-cardinality case by nature.
	maxCachedCertFailures = 128

	// certFailureTTL is how long a URL that did not yield a usable key is refused
	// without a refetch. Deliberately short: a legitimate cert URL that fails for
	// an unrelated reason must not stay poisoned, and the caller answers 503 so the
	// delivery is retried well after this expires.
	certFailureTTL = 30 * time.Second

	// maxCertBytes bounds the response read. The inbound request body limit does
	// not apply to responses we fetch.
	maxCertBytes = 16 * 1024

	certFetchTimeout = 5 * time.Second

	// maxConcurrentCertFetches bounds how many outbound cert fetches may be in
	// flight at once, across ALL urls -- see the fetchSem field doc.
	maxConcurrentCertFetches = 8
)

// certCache maps a validated signing-cert URL to its RSA public key.
//
// Caching by URL is safe because AWS mints a new URL when it rotates a cert, so
// a stale entry becomes unreachable rather than wrong. If AWS ever reused a URL
// with new key material, verification would fail until restart.
//
// Eviction is FIFO rather than LRU: with a working set of one or two, insertion
// order is sufficient and far simpler. Only a successfully parsed key is ever
// inserted, so a URL that never yields one cannot evict a working entry.
//
// Failures are tracked separately and briefly, so a REPEATED bad URL is not
// refetched on every delivery. That alone does not bound a stream of DISTINCT
// forged `.pem` URLs -- each one is a first-time miss on both the positive and
// negative cache, and still costs a real outbound fetch. What actually bounds
// that is fetchSem: a semaphore capping how many fetches, across ALL urls, may
// be in flight at once, so a flood of distinct urls queues for a fetch slot
// rather than spawning an unbounded goroutine (each holding a connection open
// for up to certFetchTimeout) per request. fetchOnce additionally collapses
// concurrent requests for the SAME url into a single fetch -- the common
// legitimate case right after AWS rotates a cert, when many deliveries can
// arrive before the first fetch populates the cache.
type certCache struct {
	mx    sync.Mutex
	keys  map[string]*rsa.PublicKey
	order []string

	failed      map[string]time.Time
	failedOrder []string

	// now is a field so the TTL is testable without sleeping.
	now func() time.Time

	fetchSem  chan struct{}
	fetchOnce singleflight.Group
}

func newCertCache() *certCache {
	return &certCache{
		keys:     make(map[string]*rsa.PublicKey, maxCachedCerts),
		failed:   make(map[string]time.Time, maxCachedCertFailures),
		now:      time.Now,
		fetchSem: make(chan struct{}, maxConcurrentCertFetches),
	}
}

func (c *certCache) get(key string) (*rsa.PublicKey, bool) {
	c.mx.Lock()
	defer c.mx.Unlock()
	pub, ok := c.keys[key]
	return pub, ok
}

func (c *certCache) put(key string, pub *rsa.PublicKey) {
	c.mx.Lock()
	defer c.mx.Unlock()

	if _, ok := c.keys[key]; ok {
		return
	}
	for len(c.order) >= maxCachedCerts {
		delete(c.keys, c.order[0])
		c.order = c.order[1:]
	}
	c.keys[key] = pub
	c.order = append(c.order, key)
}

// recentlyFailed reports whether key failed within certFailureTTL.
func (c *certCache) recentlyFailed(key string) bool {
	c.mx.Lock()
	defer c.mx.Unlock()

	at, ok := c.failed[key]
	return ok && c.now().Sub(at) < certFailureTTL
}

// putFailure records that key did not yield a usable key.
func (c *certCache) putFailure(key string) {
	c.mx.Lock()
	defer c.mx.Unlock()

	if _, ok := c.failed[key]; !ok {
		for len(c.failedOrder) >= maxCachedCertFailures {
			delete(c.failed, c.failedOrder[0])
			c.failedOrder = c.failedOrder[1:]
		}
		c.failedOrder = append(c.failedOrder, key)
	}
	c.failed[key] = c.now()
}

// publicKey returns the RSA public key for the signing cert at rawURL, fetching
// and caching it if needed. rawURL is validated against the host allowlist
// before any request is made; dial maps the validated URL to the origin to
// actually request (identity in production).
func (c *certCache) publicKey(ctx context.Context, hc *http.Client, dial func(*url.URL) *url.URL, rawURL string) (*rsa.PublicKey, error) {
	u, err := checkCertURL(rawURL)
	if err != nil {
		return nil, err
	}
	key := u.String()

	// Note the lock is not held across the fetch below: holding it would
	// serialize every request behind a single AWS call.
	if pub, ok := c.get(key); ok {
		return pub, nil
	}
	if c.recentlyFailed(key) {
		return nil, fmt.Errorf("cloudwatch: signing certificate %q failed recently", key)
	}

	// fetchOnce.Do collapses concurrent callers with the SAME key onto one fetch;
	// the semaphore acquired inside bounds how many fetches for DISTINCT keys run
	// at once. Together they are what the certCache doc comment describes -- see
	// there for why the negative cache above is not enough on its own.
	v, err, _ := c.fetchOnce.Do(key, func() (any, error) {
		select {
		case c.fetchSem <- struct{}{}:
			defer func() { <-c.fetchSem }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		return c.fetchAndParse(ctx, hc, dial, u, key)
	})
	if err != nil {
		return nil, err
	}

	return v.(*rsa.PublicKey), nil
}

// fetchAndParse does the actual outbound request and parse for publicKey, run
// under fetchOnce so concurrent callers for the same key share one call.
func (c *certCache) fetchAndParse(ctx context.Context, hc *http.Client, dial func(*url.URL) *url.URL, u *url.URL, key string) (*rsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, certFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dial(u).String(), nil)
	if err != nil {
		return nil, fmt.Errorf("cloudwatch: build cert request: %w", err)
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudwatch: fetch signing certificate: %w", err)
	}
	defer resp.Body.Close()

	// A blocked redirect also lands here, since the client is configured to
	// surface 3xx rather than follow it.
	if resp.StatusCode != http.StatusOK {
		// Negative-cached: the status is a property of this URL, so refetching it
		// changes nothing until the TTL lapses. Transport errors above deliberately
		// are not cached -- those are about connectivity, and caching them would
		// poison a legitimate cert URL through a transient blip.
		c.putFailure(key)
		return nil, fmt.Errorf("cloudwatch: fetch signing certificate: %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCertBytes))
	if err != nil {
		return nil, fmt.Errorf("cloudwatch: read signing certificate: %w", err)
	}

	// Only a successfully parsed key is cached, so a garbage body never becomes a
	// usable entry -- and, since it also never joins order, never evicts one.
	pub, err := parseCertPublicKey(body)
	if err != nil {
		c.putFailure(key)
		return nil, err
	}
	c.put(key, pub)

	return pub, nil
}
