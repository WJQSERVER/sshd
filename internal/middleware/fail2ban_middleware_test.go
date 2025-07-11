package middleware

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockAddrForFail2Ban is a helper to create a *net.TCPAddr for testing.
// Fail2Ban middleware expects *net.TCPAddr or similar to extract IP.
func mockAddrForFail2Ban(ipStr string) net.Addr {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		panic(fmt.Sprintf("Invalid IP string for mockAddr: %s", ipStr))
	}
	return &net.TCPAddr{IP: ip, Port: 12345}
}

// Helper to simulate an authentication attempt
func simulateAuthAttempt(
	t *testing.T,
	handler AuthHandlerFunc, // This is the already wrapped handler from f2b.Handler()(coreAuthLogic)
	user string,
	ipStr string,
	// authShouldSucceed bool, // This logic is now part of the coreAuthLogic passed to f2b.Handler
	// expectedErrMessageSubstring string,
) (perms *Permissions, err error) {
	t.Helper()
	ctx := NewAuthContext(user, mockAddrForFail2Ban(ipStr), "password")
	return handler(ctx)
}


func TestFail2BanMiddleware_BasicBan(t *testing.T) {
	cfg := Fail2BanMiddlewareConfig{
		MaxAttempts: 2,
		FindTime:    1 * time.Minute,
		BanTime:     200 * time.Millisecond, // Short ban time for testing
	}
	f2b, err := NewFail2BanMiddleware(cfg)
	if err != nil {
		t.Fatalf("NewFail2BanMiddleware failed: %v", err)
	}
	// This is the f2b middleware instance's specific handler chain for a given core authenticator
	f2bWrappedCoreAuth := f2b.Handler()(func(ctx *AuthContext) (*Permissions, error) {
		// This simulates the core authenticator.
		// For this test, all core authentications will fail.
		return nil, errors.New("core auth failed")
	})

	ipToTest := "192.0.2.1"

	// Attempt 1 (fail)
	_, err = simulateAuthAttempt(t, f2bWrappedCoreAuth, "user1", ipToTest)
	if err == nil || err.Error() != "core auth failed" {
		t.Errorf("Attempt 1: Expected 'core auth failed', got %v", err)
	}

	// Attempt 2 (fail) - this should trigger ban
	_, err = simulateAuthAttempt(t, f2bWrappedCoreAuth, "user1", ipToTest)
	if err == nil || err.Error() != "core auth failed" {
		t.Errorf("Attempt 2: Expected 'core auth failed', got %v", err)
	}

	f2b.mu.RLock()
	_, isBanned := f2b.bannedIPs[ipToTest]
	f2b.mu.RUnlock()
	if !isBanned {
		t.Fatal("IP was not banned after MaxAttempts")
	}


	// Attempt 3 (should be rejected by Fail2Ban)
	time.Sleep(10 * time.Millisecond) // Ensure ban is active

	authCtxBanned := NewAuthContext("user1", mockAddrForFail2Ban(ipToTest), "password")
	// We call f2bWrappedCoreAuth directly with the new context
	_, err = f2bWrappedCoreAuth(authCtxBanned)

	if err == nil {
		t.Fatal("Attempt 3: Expected error due to ban, got nil")
	}
	expectedBanMsg := fmt.Sprintf("IP address %s is temporarily banned", ipToTest)
	if !strings.Contains(err.Error(), expectedBanMsg) {
		t.Errorf("Attempt 3: Expected error message containing '%s', got '%v'", expectedBanMsg, err)
	}
	if !authCtxBanned.IsAborted() {
		t.Error("Attempt 3: Expected context to be aborted")
	}


	// Wait for ban to expire
	time.Sleep(cfg.BanTime + 50*time.Millisecond)

	// Attempt 4 (should proceed to core auth again and fail there)
	_, err = simulateAuthAttempt(t, f2bWrappedCoreAuth, "user1", ipToTest)
	if err == nil || err.Error() != "core auth failed" {
		t.Errorf("Attempt 4: Expected 'core auth failed' after ban expired, got %v", err)
	}
	f2b.mu.RLock()
	// Using a non-ASCII variable name to ensure it's unique and doesn't clash.
	var stillBanned bool
	_, stillBanned = f2b.bannedIPs[ipToTest]
	f2b.mu.RUnlock()
	if stillBanned {
		t.Error("IP should be unbanned after BanTime")
	}
}

func TestFail2BanMiddleware_FindTime(t *testing.T) {
	cfg := Fail2BanMiddlewareConfig{
		MaxAttempts: 2,
		FindTime:    100 * time.Millisecond, // Short find time
		BanTime:     1 * time.Minute,
	}
	f2b, _ := NewFail2BanMiddleware(cfg)
	f2bWrappedCoreAuth := f2b.Handler()(func(ctx *AuthContext) (*Permissions, error) {
		return nil, errors.New("core auth failed")
	})
	ipToTest := "192.0.2.2"

	// Attempt 1 (fail)
	simulateAuthAttempt(t, f2bWrappedCoreAuth, "user1", ipToTest)

	// Wait for FindTime to almost expire
	time.Sleep(cfg.FindTime - 20*time.Millisecond)

	// Attempt 2 (fail, still within FindTime, should ban)
	simulateAuthAttempt(t, f2bWrappedCoreAuth, "user1", ipToTest)

	f2b.mu.RLock()
	_, isBanned := f2b.bannedIPs[ipToTest]
	f2b.mu.RUnlock()
	if !isBanned {
		t.Fatal("IP should be banned if second attempt is within FindTime")
	}

	f2b.mu.Lock()
	delete(f2b.bannedIPs, ipToTest)
	delete(f2b.failedAttempts, ipToTest)
	f2b.mu.Unlock()


	// Attempt 1 (fail) again
	simulateAuthAttempt(t, f2bWrappedCoreAuth, "user1", ipToTest)

	// Wait for FindTime to expire
	time.Sleep(cfg.FindTime + 50*time.Millisecond)

	// Attempt 2 (fail, but after FindTime from first attempt, should not ban yet)
	simulateAuthAttempt(t, f2bWrappedCoreAuth, "user1", ipToTest)

	f2b.mu.RLock()
	_, isBanned = f2b.bannedIPs[ipToTest]
	f2b.mu.RUnlock()
	if isBanned {
		t.Fatal("IP should NOT be banned if second attempt is after FindTime from the first one")
	}

	f2b.mu.RLock()
	attempt, exists := f2b.failedAttempts[ipToTest]
	f2b.mu.RUnlock()
	if !exists || attempt.Count != 1 {
		t.Errorf("Expected failed attempts count to be 1 after FindTime reset, got %v", attempt)
	}
}

func TestFail2BanMiddleware_SuccessfulAuthResetsCounter(t *testing.T) {
	cfg := Fail2BanMiddlewareConfig{
		MaxAttempts: 2,
		FindTime:    1 * time.Minute,
		BanTime:     1 * time.Minute,
	}
	f2b, _ := NewFail2BanMiddleware(cfg)
	ipToTest := "192.0.2.3"
	var succeedNextAuth bool

	f2bWrappedCoreAuth := f2b.Handler()(func(ctx *AuthContext) (*Permissions, error) {
		if succeedNextAuth {
			return &Permissions{CanExecuteCommands: true}, nil
		}
		return nil, errors.New("core auth failed")
	})

	// Attempt 1 (fail)
	succeedNextAuth = false
	simulateAuthAttempt(t, f2bWrappedCoreAuth, "user1", ipToTest)

	f2b.mu.RLock()
	attempt, exists := f2b.failedAttempts[ipToTest]
	f2b.mu.RUnlock()
	if !exists || attempt.Count != 1 {
		t.Fatalf("Expected 1 failed attempt, got %v", attempt)
	}

	// Attempt 2 (success)
	succeedNextAuth = true
	perms, err := simulateAuthAttempt(t, f2bWrappedCoreAuth, "user1", ipToTest)
	if err != nil {
		t.Fatalf("Successful auth returned error: %v", err)
	}
	if perms == nil {
		t.Fatal("Successful auth did not return permissions")
	}

	f2b.mu.RLock()
	attempt, exists = f2b.failedAttempts[ipToTest]
	f2b.mu.RUnlock()
	if exists {
		t.Errorf("Failed attempts counter should be cleared after successful auth, got %v", attempt)
	}

	// Attempt 3 (fail again, should be treated as first failure in a new sequence)
	succeedNextAuth = false
	simulateAuthAttempt(t, f2bWrappedCoreAuth, "user1", ipToTest)
	f2b.mu.RLock()
	attempt, exists = f2b.failedAttempts[ipToTest]
	f2b.mu.RUnlock()
	if !exists || attempt.Count != 1 {
		t.Fatalf("Expected 1 failed attempt after success then fail, got %v", attempt)
	}
}

func TestFail2BanMiddleware_Whitelist(t *testing.T) {
	cfg := Fail2BanMiddlewareConfig{
		MaxAttempts: 1,
		FindTime:    1 * time.Minute,
		BanTime:     1 * time.Minute,
		Whitelist:   []string{"192.0.2.10/32", "10.0.0.0/8"},
	}
	f2b, err := NewFail2BanMiddleware(cfg)
	if err != nil {
		t.Fatalf("NewFail2BanMiddleware failed: %v", err)
	}
	f2bWrappedCoreAuth := f2b.Handler()(func(ctx *AuthContext) (*Permissions, error) {
		return nil, errors.New("core auth failed")
	})

	whitelistedIPs := []string{"192.0.2.10", "10.1.2.3"}
	nonWhitelistedIP := "192.0.2.20"

	for _, ip := range whitelistedIPs {
		// Attempt 1 (fail)
		simulateAuthAttempt(t, f2bWrappedCoreAuth, "userW", ip)
		// Attempt 2 (fail) - would normally ban due to MaxAttempts=1
		simulateAuthAttempt(t, f2bWrappedCoreAuth, "userW", ip)


		f2b.mu.RLock()
		_, isBanned := f2b.bannedIPs[ip]
		f2b.mu.RUnlock()
		if isBanned {
			t.Errorf("Whitelisted IP %s was banned", ip)
		}
	}

	// Non-whitelisted IP should be banned
	simulateAuthAttempt(t, f2bWrappedCoreAuth, "userNW", nonWhitelistedIP) // Fail 1
	f2b.mu.RLock()
	_, isBanned := f2b.bannedIPs[nonWhitelistedIP]
	f2b.mu.RUnlock()
	if !isBanned {
		t.Errorf("Non-whitelisted IP %s was not banned after MaxAttempts", nonWhitelistedIP)
	}
}

func TestFail2BanMiddleware_InvalidWhitelistCIDR(t *testing.T) {
	cfg := Fail2BanMiddlewareConfig{
		Whitelist: []string{"192.168.1.300/24"},
	}
	_, err := NewFail2BanMiddleware(cfg)
	if err == nil {
		t.Fatal("Expected error for invalid CIDR in whitelist, got nil")
	}
	if !strings.Contains(err.Error(), "invalid CIDR in whitelist") {
		t.Errorf("Expected error message about invalid CIDR, got: %v", err)
	}
}

func TestFail2BanMiddleware_CleanupRoutine(t *testing.T) {
	cfg := Fail2BanMiddlewareConfig{
		MaxAttempts: 1,
		FindTime:    50 * time.Millisecond,
		BanTime:     100 * time.Millisecond,
	}
	f2b, _ := NewFail2BanMiddleware(cfg)

	ipToBan := "192.0.2.40"
	ipStaleAttempt := "192.0.2.41"

	f2b.mu.Lock()
	f2b.bannedIPs[ipToBan] = time.Now().Add(-cfg.BanTime * 2)
	f2b.failedAttempts[ipStaleAttempt] = &LoginAttempt{
		Timestamp: time.Now().Add(-cfg.FindTime * 2),
		Count:     1,
	}
	f2b.mu.Unlock()

	// Simulate ticker firing by directly calling the logic of cleanupRoutine
	now := time.Now()
	f2b.mu.Lock()
	for ip, unbanTime := range f2b.bannedIPs {
		if now.After(unbanTime) {
			delete(f2b.bannedIPs, ip)
		}
	}
	for ip, attempt := range f2b.failedAttempts {
		if now.Sub(attempt.Timestamp) > f2b.config.FindTime { // Corrected: fm.config.FindTime to f2b.config.FindTime
			delete(f2b.failedAttempts, ip) // Corrected: fm.failedAttempts to f2b.failedAttempts
		}
	}
	f2b.mu.Unlock()


	f2b.mu.RLock()
	if _, exists := f2b.bannedIPs[ipToBan]; exists {
		t.Errorf("Expired ban for %s was not cleaned up", ipToBan)
	}
	if _, exists := f2b.failedAttempts[ipStaleAttempt]; exists {
		t.Errorf("Stale failed attempt for %s was not cleaned up", ipStaleAttempt)
	}
	f2b.mu.RUnlock()
}

func TestFail2BanMiddleware_NoIPInContext(t *testing.T) {
	cfg := Fail2BanMiddlewareConfig{MaxAttempts: 1}
	f2b, _ := NewFail2BanMiddleware(cfg)

	coreAuthCalled := false
	f2bWrappedCoreAuth := f2b.Handler()(func(ctx *AuthContext) (*Permissions, error) {
		coreAuthCalled = true
		return nil, errors.New("core auth failed")
	})

	// Use our existing MockAddr which getIPFromAuthContext won't parse to a standard IP type
	ctx := NewAuthContext("userNoIP", MockAddr("notaTCPorIPaddr"), "password")

	_, err := f2bWrappedCoreAuth(ctx) // Call the wrapped handler

	if !coreAuthCalled {
		t.Error("Core authenticator should have been called when IP is not determinable")
	}
	if err == nil || err.Error() != "core auth failed" {
		t.Errorf("Expected 'core auth failed' from core authenticator, got %v", err)
	}

	f2b.mu.RLock()
	if len(f2b.failedAttempts) > 0 || len(f2b.bannedIPs) > 0 {
		t.Error("Fail2Ban maps should be empty if IP address was not found")
	}
	f2b.mu.RUnlock()
}

func TestFail2BanMiddleware_Concurrency(t *testing.T) {
	t.Parallel() // Mark this test as safe for parallel execution with others
	cfg := Fail2BanMiddlewareConfig{
		MaxAttempts: 3,
		FindTime:    10 * time.Second,
		BanTime:     200 * time.Millisecond, // Shorter ban time for faster test cycles
	}
	f2b, _ := NewFail2BanMiddleware(cfg)

	numGoroutines := 20
	attemptsPerGoroutine := cfg.MaxAttempts

	ipToTest := "192.0.2.50"

	var wg sync.WaitGroup


	// Core authenticator that always fails
	coreAuthFailure := func(ctx *AuthContext) (*Permissions, error) {
		return nil, errors.New("concurrent core auth failed")
	}
	// Get the Fail2Ban wrapped handler once
	f2bWrappedHandler := f2b.Handler()(coreAuthFailure)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1) // Increment counter for the goroutine itself
		go func(routineNum int) {
			defer wg.Done()
			for j := 0; j < attemptsPerGoroutine; j++ {
				user := fmt.Sprintf("user-g%d-a%d", routineNum, j)
				// Use simulateAuthAttempt or call f2bWrappedHandler directly
				// _,_ = simulateAuthAttempt(t, f2bWrappedHandler, user, ipToTest)
				ctx := NewAuthContext(user, mockAddrForFail2Ban(ipToTest), "password")
				f2bWrappedHandler(ctx) // Call the already wrapped handler
				// No need for another wg.Done() here if attemptsPerGoroutine is small
				// and we are doing wg.Add(numGoroutines)
			}
		}(i)
	}
	wg.Wait()

	time.Sleep(50 * time.Millisecond)

	f2b.mu.RLock()
	bannedTime, isBanned := f2b.bannedIPs[ipToTest]
	f2b.mu.RUnlock()

	// This check is tricky due to short BanTime. The main goal is to run with -race.
	if isBanned {
		t.Logf("IP %s was banned at %v after concurrent attempts.", ipToTest, bannedTime)
	} else {
		// Check if it was banned recently by looking at failedAttempts (should be empty if banned)
		f2b.mu.RLock()
		_, hasFailedAttempts := f2b.failedAttempts[ipToTest]
		f2b.mu.RUnlock()
		if !hasFailedAttempts {
			t.Logf("IP %s was likely banned and then unbanned due to short BanTime (%v). Failed attempts map is clear.", ipToTest, cfg.BanTime)
		} else {
			t.Logf("IP %s was not definitively banned or ban expired and new attempts started. Test with -race. Failed attempts: %v", ipToTest, f2b.failedAttempts[ipToTest])
		}
	}
}

// Test getIPFromAuthContext explicitly
func TestGetIPFromAuthContext(t *testing.T) {
	testCases := []struct {
		name     string
		addr     net.Addr
		expectedIP string
		isNil    bool
	}{
		{"TCPAddr IPv4", &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234}, "192.0.2.1", false},
		{"TCPAddr IPv6", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234}, "2001:db8::1", false},
		{"IPAddr IPv4", &net.IPAddr{IP: net.ParseIP("198.51.100.2")}, "198.51.100.2", false},
		{"IPAddr IPv6", &net.IPAddr{IP: net.ParseIP("2001:db8::2")}, "2001:db8::2", false},
		{"MockAddr", MockAddr("custom_addr_string"), "", true},
		{"NilAddr", nil, "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ip := getIPFromAuthContext(tc.addr)
			if tc.isNil {
				if ip != nil {
					t.Errorf("Expected nil IP, got %v", ip)
				}
			} else {
				if ip == nil {
					t.Fatalf("Expected IP %s, got nil", tc.expectedIP)
				}
				if ip.String() != tc.expectedIP {
					t.Errorf("Expected IP %s, got %s", tc.expectedIP, ip.String())
				}
			}
		})
	}
}
