package cloudwatch

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// certURL builds an allowlisted signing-cert URL. The path matters: checkCertURL
// requires a single *.pem segment.
func certURL(name string) string {
	return "https://sns.us-west-2.amazonaws.com/SimpleNotificationService-" + name + ".pem"
}

// certServer serves body for every request and counts the hits it receives, so a
// test can assert that a fetch did or did not happen. dial redirects the cache at
// it while leaving the allowlist to run against the real URL.
func certServer(t *testing.T, handler http.HandlerFunc) (dial func(*url.URL) *url.URL, hits *atomic.Int32) {
	t.Helper()

	hits = new(atomic.Int32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)

	base, err := url.Parse(srv.URL)
	require.NoError(t, err)

	return func(u *url.URL) *url.URL {
		out := *u
		out.Scheme = base.Scheme
		out.Host = base.Host
		return &out
	}, hits
}

func TestCertCache_CachesOnSuccess(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemData := selfSignedPEM(t, key)

	dial, hits := certServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(pemData)
	})

	c := newCertCache()
	u := certURL("a")

	first, err := c.publicKey(context.Background(), &http.Client{}, dial, u)
	require.NoError(t, err)
	assert.Equal(t, key.N, first.N)
	assert.EqualValues(t, 1, hits.Load())

	second, err := c.publicKey(context.Background(), &http.Client{}, dial, u)
	require.NoError(t, err)
	assert.Equal(t, first, second)
	assert.EqualValues(t, 1, hits.Load(), "a cached key must not refetch")
}

// TestCertCache_GarbageBodyCachesNothing pins the invariant that only a parsed
// key is stored, so a URL that returns junk cannot become a usable entry.
func TestCertCache_GarbageBodyCachesNothing(t *testing.T) {
	dial, _ := certServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not a pem block"))
	})

	c := newCertCache()
	_, err := c.publicKey(context.Background(), &http.Client{}, dial, certURL("junk"))
	require.Error(t, err)

	_, ok := c.get(certURL("junk"))
	assert.False(t, ok, "an unparseable body must not be cached as a key")
}

// TestCertCache_NegativeCacheSuppressesRefetch covers the abuse case: a URL that
// cannot yield a key must not cost an outbound fetch on every delivery.
func TestCertCache_NegativeCacheSuppressesRefetch(t *testing.T) {
	dial, hits := certServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	c := newCertCache()
	u := certURL("missing")

	_, err := c.publicKey(context.Background(), &http.Client{}, dial, u)
	require.Error(t, err)
	assert.EqualValues(t, 1, hits.Load())

	_, err = c.publicKey(context.Background(), &http.Client{}, dial, u)
	require.Error(t, err)
	assert.EqualValues(t, 1, hits.Load(), "a recently failed URL must not refetch")

	// Past the TTL the URL is retried, so a transient failure cannot poison a
	// legitimate cert URL permanently.
	c.mx.Lock()
	c.failed[u] = c.failed[u].Add(-certFailureTTL - time.Second)
	c.mx.Unlock()

	_, err = c.publicKey(context.Background(), &http.Client{}, dial, u)
	require.Error(t, err)
	assert.EqualValues(t, 2, hits.Load(), "the URL must be retried once the TTL lapses")
}

// TestCertCache_FailuresDoNotEvictWorkingEntry pins that failure traffic cannot
// push a good cert out of the cache: only successful parses join the FIFO.
func TestCertCache_FailuresDoNotEvictWorkingEntry(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemData := selfSignedPEM(t, key)

	good := certURL("good")
	dial, _ := certServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "good") {
			_, _ = w.Write(pemData)
			return
		}
		http.NotFound(w, r)
	})

	c := newCertCache()
	_, err = c.publicKey(context.Background(), &http.Client{}, dial, good)
	require.NoError(t, err)

	// Far more distinct failing URLs than maxCachedCerts.
	for i := 0; i < maxCachedCerts*4; i++ {
		_, err := c.publicKey(context.Background(), &http.Client{}, dial, certURL(fmt.Sprintf("bad-%d", i)))
		require.Error(t, err)
	}

	_, ok := c.get(good)
	assert.True(t, ok, "failure traffic must not evict a working entry")
	assert.LessOrEqual(t, len(c.failed), maxCachedCertFailures, "the negative cache must stay bounded")
}

// TestCertCache_EvictsAtBound covers FIFO eviction once maxCachedCerts distinct
// certs have been cached successfully.
func TestCertCache_EvictsAtBound(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemData := selfSignedPEM(t, key)

	dial, _ := certServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(pemData)
	})

	c := newCertCache()
	for i := 0; i < maxCachedCerts+5; i++ {
		_, err := c.publicKey(context.Background(), &http.Client{}, dial, certURL(fmt.Sprintf("c-%d", i)))
		require.NoError(t, err)
	}

	assert.Len(t, c.keys, maxCachedCerts, "cache must stay at its bound")
	_, ok := c.get(certURL("c-0"))
	assert.False(t, ok, "the oldest entry must be evicted first")
	_, ok = c.get(certURL(fmt.Sprintf("c-%d", maxCachedCerts+4)))
	assert.True(t, ok, "the newest entry must be retained")
}

// TestCertCache_TruncatesOversizeBody pins maxCertBytes. A body past the limit is
// cut off, so it no longer parses -- an endpoint cannot stream unbounded data
// into this handler.
func TestCertCache_TruncatesOversizeBody(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemData := selfSignedPEM(t, key)
	require.Less(t, len(pemData), maxCertBytes, "a real cert must fit inside the limit")

	dial, _ := certServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("A", maxCertBytes)))
		_, _ = w.Write(pemData)
	})

	c := newCertCache()
	_, err = c.publicKey(context.Background(), &http.Client{}, dial, certURL("huge"))
	require.Error(t, err, "a body pushed past maxCertBytes must not parse")
}

// TestCertCache_RejectsBadURLBeforeFetch pins that the allowlist runs first: a
// disallowed host must cost no outbound request at all.
func TestCertCache_RejectsBadURLBeforeFetch(t *testing.T) {
	dial, hits := certServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("should never be reached"))
	})

	c := newCertCache()
	_, err := c.publicKey(context.Background(), &http.Client{}, dial,
		"https://sns.us-west-2.amazonaws.com.evil.com/x.pem")
	require.Error(t, err)
	assert.EqualValues(t, 0, hits.Load(), "a disallowed host must not be fetched")
}
