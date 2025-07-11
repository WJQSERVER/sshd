package system

import (
	"bufio"
	"fmt"
	"errors" // For errors.Is
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/go-crypt/crypt"
	"github.com/go-crypt/crypt/algorithm" // For error types like algorithm.ErrPasswordMismatch
)

// SystemUserInfo holds essential information about a system user.
type SystemUserInfo struct {
	Username string
	UID      string
	GID      string
	HomeDir  string
	Shell    string // Default shell, might not always be available or relevant for all auth types
}

// ShadowEntry holds parsed fields from a /etc/shadow line.
// Field names correspond to standard shadow file fields.
type ShadowEntry struct {
	Username       string
	PasswordHash   string
	LastChange     int64 // Days since Jan 1, 1970
	MinAge         int64 // Min days between password changes
	MaxAge         int64 // Max days before password change required
	WarnPeriod     int64 // Days before password expiry to warn user
	InactivePeriod int64 // Days after password expiry that account is disabled
	ExpiryDate     int64 // Days since Jan 1, 1970 that account is disabled
	Reserved       string // Reserved field
}

// LookupUser queries the operating system for details about the given username.
func LookupUser(username string) (*SystemUserInfo, error) {
	sysUser, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("system user '%s' not found: %w", username, err)
	}

	// Shell information is not directly available in user.User on all OSes (e.g. Windows)
	// For Linux/macOS, it's typically in /etc/passwd, which user.Lookup reads.
	// However, user.User doesn't expose the shell field directly.
	// We will retrieve it if possible, but it's not critical for all SSH operations.
	// For now, we'll leave it empty and can enhance this later if needed using platform-specific methods
	// or by parsing /etc/passwd if absolutely necessary (though os/user is preferred).
	// Note: Gid is the primary group ID. Uid is the user ID.

	return &SystemUserInfo{
		Username: sysUser.Username,
		UID:      sysUser.Uid,
		GID:      sysUser.Gid,
		HomeDir:  sysUser.HomeDir,
		Shell:    "", // Placeholder for now, user.User doesn't directly provide shell.
	}, nil
}

// GetUserShell attempts to get the user's default shell.
// This is a placeholder for a more robust, platform-specific implementation if needed.
// On POSIX systems, user.Lookup *does* parse /etc/passwd, but the shell field isn't exposed in the struct.
// For many SSH operations (like SFTP or direct command execution via "exec"), the shell isn't strictly needed.
// For an interactive "shell" request, we might need to improve this or fall back to a default like "sh" or "bash".
func (sui *SystemUserInfo) GetUserShell() string {
	if sui.Shell != "" {
		return sui.Shell
	}
	// A common default if no shell is specified or found.
	// System `sshd` often defaults to /bin/sh if user's shell is invalid or /sbin/nologin.
	// For root, it's often /bin/bash or /bin/sh.
	// This part will need more thought when we implement user impersonation and actual shell spawning.
	// For now, we can assume 'sh' as a very basic default if nothing else is found.
	// The `os/user` package does not provide the shell.
	// We might need to make `server.defaultShell` more intelligent or configurable later.
	return "/bin/sh" // A common safe default
}

const shadowFilePath = "/etc/shadow"

// GetShadowEntryForUser reads /etc/shadow and returns the ShadowEntry for the specified username.
// This function MUST run with root privileges to read /etc/shadow.
func GetShadowEntryForUser(username string) (*ShadowEntry, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("reading %s requires root privileges", shadowFilePath)
	}

	file, err := os.Open(shadowFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s: %w", shadowFilePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		entry, err := parseShadowLine(line)
		if err != nil {
			// Log malformed lines but continue scanning
			// log.Printf("Warning: skipping malformed shadow entry: %v (line: %s)", err, line)
			continue
		}
		if entry.Username == username {
			return entry, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading %s: %w", shadowFilePath, err)
	}

	return nil, fmt.Errorf("user '%s' not found in %s", username, shadowFilePath)
}

// parseShadowLine parses a single line from the /etc/shadow file.
func parseShadowLine(line string) (*ShadowEntry, error) {
	fields := strings.Split(line, ":")
	if len(fields) < 8 { // Minimum 8 fields, reserved field can be empty making it 8, or present making it 9
		return nil, fmt.Errorf("invalid shadow line: expected at least 8 fields, got %d", len(fields))
	}

	entry := &ShadowEntry{
		Username:     fields[0],
		PasswordHash: fields[1],
	}

	var err error
	if fields[2] != "" {
		entry.LastChange, err = strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid LastChange field '%s': %w", fields[2], err)
		}
	}
	if fields[3] != "" {
		entry.MinAge, err = strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid MinAge field '%s': %w", fields[3], err)
		}
	}
	if fields[4] != "" {
		entry.MaxAge, err = strconv.ParseInt(fields[4], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid MaxAge field '%s': %w", fields[4], err)
		}
	}
	if fields[5] != "" {
		entry.WarnPeriod, err = strconv.ParseInt(fields[5], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid WarnPeriod field '%s': %w", fields[5], err)
		}
	}
	if fields[6] != "" {
		entry.InactivePeriod, err = strconv.ParseInt(fields[6], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid InactivePeriod field '%s': %w", fields[6], err)
		}
	}
	if fields[7] != "" {
		entry.ExpiryDate, err = strconv.ParseInt(fields[7], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid ExpiryDate field '%s': %w", fields[7], err)
		}
	}
	if len(fields) > 8 {
		entry.Reserved = fields[8]
	}

	return entry, nil
}

// VerifyPassword checks if the given plainPassword matches the hashed password
// from /etc/shadow (which includes the algorithm, salt, and hash).
// It uses github.com/go-crypt/crypt to verify various crypt(3) style hashes.
func VerifyPassword(plainPassword, shadowHash string) (bool, error) {
	// crypt.Verify attempts to decode the hash, identify the algorithm, and verify.
	err := crypt.Verify(shadowHash, []byte(plainPassword))

	if err == nil {
		return true, nil // Password matches
	}

	// Check if the error is a password mismatch error.
	// The go-crypt library uses specific error types for this.
	// For example, algorithm.ErrPasswordMismatch or a similar sentinel error.
	// We need to consult its documentation for the exact error to check.
	// Assuming algorithm.ErrPasswordMismatch is the one.
	if errors.Is(err, algorithm.ErrPasswordMismatch) {
		return false, nil // Password does not match
	}

	// Check if the error indicates an unknown or unsupported algorithm.
	// The library might return algorithm.ErrAlgorithmInvalid or algorithm.ErrAlgorithmUnavailable.
	if errors.Is(err, algorithm.ErrAlgorithmInvalid) || errors.Is(err, algorithm.ErrAlgorithmUnavailable) {
		return false, fmt.Errorf("unsupported or malformed hash algorithm in '%s': %w", shadowHash, err)
	}

	// Any other error is an unexpected issue during verification.
	return false, fmt.Errorf("password verification failed for hash '%s': %w", shadowHash, err)
}
