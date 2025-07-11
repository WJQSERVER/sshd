package system

import (
	"fmt"
	"os/user"
)

// SystemUserInfo holds essential information about a system user.
type SystemUserInfo struct {
	Username string
	UID      string
	GID      string
	HomeDir  string
	Shell    string // Default shell, might not always be available or relevant for all auth types
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
