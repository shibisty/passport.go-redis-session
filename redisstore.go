// Package redisstore implements passport.SessionStore on top of orm.KeyValueStore.
// gtr package: passport-session-redis.
//
// Any store implementing orm.KeyValueStore works; usually this is Redis
// via orm-redis. Sessions are visible to all application instances.
//
//	conn, _ := orm.New(ctx, redis.Driver("redis://localhost:6379/0"))
//	sessions := redisstore.New(conn.(orm.KeyValueStore))
//	a := passport.New().UseSessionStore(sessions)
package redisstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"orm"
	"passport"
	"passport/memorystore"
)

// DefaultPrefix is the session key prefix.
const DefaultPrefix = "session:"

// Store implements passport.SessionStore.
type Store struct {
	kv     orm.KeyValueStore
	prefix string
}

// New wraps an open connection.
func New(kv orm.KeyValueStore) *Store {
	return &Store{kv: kv, prefix: DefaultPrefix}
}

// WithPrefix sets the key prefix (e.g. "myapp:session:").
func (s *Store) WithPrefix(prefix string) *Store {
	s.prefix = prefix
	return s
}

// Create stores a session. The TTL is rounded up to whole seconds (at least
// one): Redis stores expiry in seconds, and a TTL of 0 would mean "forever".
func (s *Store) Create(ctx context.Context, identity *passport.Identity, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", fmt.Errorf("redisstore: TTL must be greater than zero, got %s", ttl)
	}
	id, err := memorystore.NewID()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(identity) // Raw is tagged json:"-" and is not stored
	if err != nil {
		return "", err
	}
	seconds := int((ttl + time.Second - 1) / time.Second)
	if err := s.kv.Set(ctx, s.key(id), string(data), seconds); err != nil {
		return "", err
	}
	return id, nil
}

// Get returns passport.ErrSessionNotFound if the session does not exist; store
// errors (e.g. Redis being unavailable) are returned as is — they must not
// be passed off as "not logged in".
func (s *Store) Get(ctx context.Context, sessionID string) (*passport.Identity, error) {
	if sessionID == "" {
		return nil, passport.ErrSessionNotFound
	}
	raw, err := s.kv.Get(ctx, s.key(sessionID))
	if errors.Is(err, orm.ErrNotFound) {
		return nil, passport.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redisstore: %w", err)
	}
	var identity passport.Identity
	if err := json.Unmarshal([]byte(raw), &identity); err != nil {
		return nil, fmt.Errorf("redisstore: corrupted session: %w", err)
	}
	return &identity, nil
}

// Destroy deletes a session; a missing session is not an error.
func (s *Store) Destroy(ctx context.Context, sessionID string) error {
	_, err := s.kv.Del(ctx, s.key(sessionID))
	return err
}

// key is the Redis key of a session: the prefix and the SHA-256 of its ID,
// so listing the keys (KEYS, a dump, a replica) does not give away live
// session IDs.
func (s *Store) key(sessionID string) string { return s.prefix + Key(sessionID) }

// Key is the stored form of a session ID (hex SHA-256), without the prefix.
func Key(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(sum[:])
}

var _ passport.SessionStore = (*Store)(nil)
