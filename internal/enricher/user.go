package enricher

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
)

// UserResolver caches UID to system username mappings.
type UserResolver struct {
	cache sync.Map // map[uint32]string
}

// NewUserResolver initializes the resolver and pre-populates common system accounts.
func NewUserResolver() *UserResolver {
	ur := &UserResolver{}
	ur.cache.Store(uint32(0), "root")
	ur.loadEtcPasswd()
	return ur
}

// Resolve returns the username for a given UID, caching the result.
func (ur *UserResolver) Resolve(uid uint32) string {
	if val, ok := ur.cache.Load(uid); ok {
		return val.(string)
	}

	// 1. Try standard library lookup
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err == nil && u.Username != "" {
		ur.cache.Store(uid, u.Username)
		return u.Username
	}

	// 2. Fallback to string UID representation
	fallback := fmt.Sprintf("uid(%d)", uid)
	ur.cache.Store(uid, fallback)
	return fallback
}

// loadEtcPasswd loads system usernames from /etc/passwd if readable.
func (ur *UserResolver) loadEtcPasswd() {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			uname := parts[0]
			uidVal, err := strconv.ParseUint(parts[2], 10, 32)
			if err == nil {
				ur.cache.Store(uint32(uidVal), uname)
			}
		}
	}
}
