package middleware

import (
	"errors"
	"strings"
	"testing"
)

// MockAddr 用于测试, 实现了 net.Addr 接口
type MockAddr string

func (m MockAddr) Network() string { return "mock" }
func (m MockAddr) String() string  { return string(m) }

// TestAuthContext 测试 AuthContext 的基本功能
func TestAuthContext(t *testing.T) {
	ctx := NewAuthContext("testuser", MockAddr("127.0.0.1:12345"), "password")

	if ctx.User != "testuser" {
		t.Errorf("Expected user 'testuser', got '%s'", ctx.User)
	}
	if ctx.RemoteAddr.String() != "127.0.0.1:12345" {
		t.Errorf("Expected remote addr '127.0.0.1:12345', got '%s'", ctx.RemoteAddr.String())
	}
	if ctx.AuthMethod != "password" {
		t.Errorf("Expected auth method 'password', got '%s'", ctx.AuthMethod)
	}

	// Test Set/Get
	ctx.Set("key1", "value1")
	val, ok := ctx.Get("key1")
	if !ok || val.(string) != "value1" {
		t.Errorf("Set/Get failed, expected 'value1', got '%v'", val)
	}

	_, ok = ctx.Get("nonexistentkey")
	if ok {
		t.Error("Expected Get for nonexistent key to return !ok")
	}

	// Test Abort
	if ctx.IsAborted() {
		t.Error("Context should not be aborted initially")
	}
	ctx.Abort()
	if !ctx.IsAborted() {
		t.Error("Context should be aborted after Abort()")
	}
	if ctx.Error() != nil {
		t.Errorf("Expected nil error after Abort(), got %v", ctx.Error())
	}

	// Test AbortWithError
	customErr := errors.New("custom abort error")
	ctx = NewAuthContext("testuser2", MockAddr("127.0.0.2:12345"), "publickey") // fresh context
	ctx.AbortWithError(customErr)
	if !ctx.IsAborted() {
		t.Error("Context should be aborted after AbortWithError()")
	}
	if ctx.Error() != customErr {
		t.Errorf("Expected error '%v', got '%v'", customErr, ctx.Error())
	}
}

// TestMiddlewareChainExecutionOrder 测试中间件执行顺序和数据传递
func TestMiddlewareChainExecutionOrder(t *testing.T) {
	var executionOrder []string // 用于记录执行顺序

	mw1 := func(next AuthHandlerFunc) AuthHandlerFunc {
		return func(ctx *AuthContext) (*Permissions, error) {
			executionOrder = append(executionOrder, "mw1-in")
			ctx.Set("mw1-data", "data_from_mw1")
			perm, err := next(ctx)
			executionOrder = append(executionOrder, "mw1-out")
			return perm, err
		}
	}

	mw2 := func(next AuthHandlerFunc) AuthHandlerFunc {
		return func(ctx *AuthContext) (*Permissions, error) {
			executionOrder = append(executionOrder, "mw2-in")
			data, _ := ctx.Get("mw1-data")
			if data.(string) != "data_from_mw1" {
				t.Errorf("mw2 did not receive data from mw1")
			}
			ctx.Set("mw2-data", "data_from_mw2")
			perm, err := next(ctx)
			executionOrder = append(executionOrder, "mw2-out")
			return perm, err
		}
	}

	coreHandler := func(ctx *AuthContext) (*Permissions, error) {
		executionOrder = append(executionOrder, "core")
		data1, _ := ctx.Get("mw1-data")
		data2, _ := ctx.Get("mw2-data")
		if data1.(string) != "data_from_mw1" || data2.(string) != "data_from_mw2" {
			t.Errorf("core handler did not receive data from middlewares")
		}
		return &Permissions{CanExecuteCommands: true}, nil
	}

	builder := NewChainBuilder()
	builder.Use(mw1, mw2)
	chainedHandler := builder.Then(coreHandler)

	authCtx := NewAuthContext("test", MockAddr("1.2.3.4:123"), "testmethod")
	perms, err := chainedHandler(authCtx)

	if err != nil {
		t.Fatalf("Chained handler returned an error: %v", err)
	}
	if perms == nil || !perms.CanExecuteCommands {
		t.Errorf("Chained handler did not return expected permissions")
	}

	expectedOrder := []string{"mw1-in", "mw2-in", "core", "mw2-out", "mw1-out"}
	if strings.Join(executionOrder, ",") != strings.Join(expectedOrder, ",") {
		t.Errorf("Execution order mismatch. Expected: %v, Got: %v", expectedOrder, executionOrder)
	}

	// Test with Chain function directly
	executionOrder = []string{} // Reset
	chainedHandlerDirect := Chain(coreHandler, mw1, mw2)
	authCtx2 := NewAuthContext("test2", MockAddr("1.2.3.5:123"), "testmethod2")
	_, _ = chainedHandlerDirect(authCtx2)
	if strings.Join(executionOrder, ",") != strings.Join(expectedOrder, ",") {
		t.Errorf("Execution order mismatch (Chain direct). Expected: %v, Got: %v", expectedOrder, executionOrder)
	}
}

// TestMiddlewareChainAbort 测试中间件中止链的执行
func TestMiddlewareChainAbort(t *testing.T) {
	var mw1Executed, mw2Executed, coreExecuted bool
	abortErr := errors.New("aborted by mw1")

	mw1 := func(next AuthHandlerFunc) AuthHandlerFunc {
		return func(ctx *AuthContext) (*Permissions, error) {
			mw1Executed = true
			ctx.AbortWithError(abortErr) // mw1 中止
			// 理论上, 即使调用 next(ctx), 由于上下文已中止,
			// 后续中间件和核心处理器在检查 IsAborted 时应该提前返回.
			// 或者, next(ctx) 本身可能就会因为 ctx.IsAborted() 而直接返回 ctx.Error().
			// 为了确保测试覆盖到链的短路行为, 我们依赖于后续组件正确处理 IsAborted.
			// 这里的 next(ctx) 调用是为了模拟一个中间件在中止后仍然调用下一个环节的场景.
			// 规范的链式调用应该在 next(ctx) 返回后检查 ctx.IsAborted() 或 ctx.Error().
			// 但更常见的做法是在调用 next(ctx) 之前检查.
			// 我们的 ChainBuilder 实现应该确保这种中止能正确传播.

			// 为了更严格地测试中止传播, 我们让 next(ctx) 在此被调用,
			// 并期望即使它被调用, 其内部逻辑 (mw2Executed, coreExecuted) 不会执行.
			// 这依赖于 ChainBuilder 包装的函数能正确处理 IsAborted.
			// 实际上,我们的 ChainBuilder 的构建方式 (m1(m2(core))) 意味着
			// 如果 m1 中止并返回, m2 和 core 就不会被 m1 调用.
			// 如果 m1 中止了 ctx, 然后调用了 next (即 m2 的包装器),
			// 那么 m2 的包装器应该在其开始处检查 ctx.IsAborted() 并立即返回.

			// 实际上, 当 ctx.AbortWithError 被调用后, ctx.Error() 就会返回那个错误.
			// 如果中间件在中止后还调用 next(ctx), 那么 next(ctx) 应该简单地返回 (nil, ctx.Error()).
			// 让我们假设中间件在中止后就直接返回.
			return nil, ctx.Error() // 直接返回错误, 不再调用 next
		}
	}

	mw2 := func(next AuthHandlerFunc) AuthHandlerFunc {
		return func(ctx *AuthContext) (*Permissions, error) {
			// 这个中间件的内部逻辑不应该被执行如果前一个中止了
			// 为确保这一点, 我们检查 IsAborted.
			if ctx.IsAborted() {
				return nil, ctx.Error()
			}
			mw2Executed = true
			return next(ctx)
		}
	}

	coreHandler := func(ctx *AuthContext) (*Permissions, error) {
		if ctx.IsAborted() {
			return nil, ctx.Error()
		}
		coreExecuted = true
		return nil, nil
	}

	builder := NewChainBuilder()
	builder.Use(mw1, mw2)
	chainedHandler := builder.Then(coreHandler)

	authCtx := NewAuthContext("test-abort", MockAddr("4.3.2.1:321"), "testabort")
	perms, err := chainedHandler(authCtx)

	if !mw1Executed {
		t.Error("mw1 should have been executed")
	}
	if mw2Executed {
		t.Error("mw2 should not have been executed after abort in mw1")
	}
	if coreExecuted {
		t.Error("coreHandler should not have been executed after abort in mw1")
	}
	if perms != nil {
		t.Error("Permissions should be nil after abort")
	}
	if err != abortErr {
		t.Errorf("Expected error '%v', got '%v'", abortErr, err)
	}
	if !authCtx.IsAborted() {
		t.Error("AuthContext should be marked as aborted")
	}
}

// TestMiddlewareChain_NilFinalHandler tests ChainBuilder.Then(nil)
func TestMiddlewareChain_NilFinalHandler(t *testing.T) {
	var mw1Called bool
	mw1 := func(next AuthHandlerFunc) AuthHandlerFunc {
		return func(ctx *AuthContext) (*Permissions, error) {
			mw1Called = true
			return next(ctx)
		}
	}

	builder := NewChainBuilder()
	builder.Use(mw1)
	chainedHandler := builder.Then(nil)

	authCtx := NewAuthContext("test-nil-final", MockAddr("1.1.1.1:111"), "nilfinal")
	perms, err := chainedHandler(authCtx)

	if !mw1Called {
		t.Error("Expected mw1 to be called")
	}
	if err != nil {
		t.Errorf("Expected no error from default nil final handler, got %v", err)
	}
	if perms != nil {
		t.Errorf("Expected no permissions from default nil final handler, got %v", perms)
	}
	if authCtx.IsAborted() && authCtx.Error() == nil { // 如果中止了但没有错误, 也是符合预期的
		// this is fine
	} else if authCtx.IsAborted() && authCtx.Error() != nil {
		t.Errorf("Expected no error or nil error if aborted by default handler, got %v", authCtx.Error())
	}


	// Test Chain with nil final handler
	mw1Called = false // reset
	chainedHandlerDirect := Chain(nil, mw1)
	authCtx2 := NewAuthContext("test-nil-final2", MockAddr("1.1.1.2:111"), "nilfinal2")
	perms2, err2 := chainedHandlerDirect(authCtx2)
	if !mw1Called {
		t.Error("Expected mw1 to be called (Chain direct)")
	}
	if err2 != nil {
		t.Errorf("Expected no error from default nil final handler (Chain direct), got %v", err2)
	}
	if perms2 != nil {
		t.Errorf("Expected no permissions from default nil final handler (Chain direct), got %v", perms2)
	}
}

// TestMiddlewareChain_EmptyChain tests an empty middleware chain
func TestMiddlewareChain_EmptyChain(t *testing.T) {
	var coreCalled bool
	coreHandler := func(ctx *AuthContext) (*Permissions, error) {
		coreCalled = true
		return &Permissions{CanPortForward: true}, nil
	}

	builder := NewChainBuilder()
	chainedHandler := builder.Then(coreHandler)

	authCtx := NewAuthContext("test-empty", MockAddr("2.2.2.2:222"), "empty")
	perms, err := chainedHandler(authCtx)

	if !coreCalled {
		t.Error("Expected coreHandler to be called in an empty chain")
	}
	if err != nil {
		t.Errorf("Expected no error from empty chain, got %v", err)
	}
	if perms == nil || !perms.CanPortForward {
		t.Errorf("Expected permissions from coreHandler, got %v", perms)
	}

	coreCalled = false // reset
	chainedHandlerDirect := Chain(coreHandler)
	authCtx2 := NewAuthContext("test-empty2", MockAddr("2.2.2.3:222"), "empty2")
	_, _ = chainedHandlerDirect(authCtx2)
	if !coreCalled {
		t.Error("Expected coreHandler to be called (Chain direct, no middlewares)")
	}
}


// TestMiddlewareChain_AbortInFinalHandler tests if abort in final handler propagates
func TestMiddlewareChain_AbortInFinalHandler(t *testing.T) {
	finalErr := errors.New("aborted in final handler")
	coreHandler := func(ctx *AuthContext) (*Permissions, error) {
		ctx.AbortWithError(finalErr)
		return nil, ctx.Error() //  重要: 返回 ctx.Error()
	}

	builder := NewChainBuilder()
	// No middlewares, just the core handler
	chainedHandler := builder.Then(coreHandler)

	authCtx := NewAuthContext("test-final-abort", MockAddr("3.3.3.3:333"), "finalabort")
	perms, err := chainedHandler(authCtx)

	if !authCtx.IsAborted() {
		t.Error("Expected context to be aborted by final handler")
	}
	if err != finalErr {
		t.Errorf("Expected error '%v', got '%v'", finalErr, err)
	}
	if perms != nil {
		t.Error("Expected nil permissions when final handler aborts")
	}
}
