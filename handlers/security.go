package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// Security headers middleware
func SecurityHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		
		// Enable XSS protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		
		// Referrer policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		
		// Content Security Policy
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;")
		
		// Strict Transport Security (if using HTTPS)
		// w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		
		next(w, r)
	}
}

// CSRF protection
type CSRFStore struct {
	tokens map[string]time.Time
	mu     sync.RWMutex
}

var csrfStore = &CSRFStore{
	tokens: make(map[string]time.Time),
}

// Generate CSRF token
func GenerateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	token := base64.URLEncoding.EncodeToString(b)
	
	csrfStore.mu.Lock()
	csrfStore.tokens[token] = time.Now().Add(1 * time.Hour)
	csrfStore.mu.Unlock()
	
	// Clean up expired tokens
	go cleanExpiredTokens()
	
	return token
}

// Validate CSRF token
func ValidateCSRFToken(token string) bool {
	csrfStore.mu.RLock()
	expiry, exists := csrfStore.tokens[token]
	csrfStore.mu.RUnlock()
	
	if !exists {
		return false
	}
	
	if time.Now().After(expiry) {
		csrfStore.mu.Lock()
		delete(csrfStore.tokens, token)
		csrfStore.mu.Unlock()
		return false
	}
	
	return true
}

// Remove token after use
func ConsumeCSRFToken(token string) {
	csrfStore.mu.Lock()
	delete(csrfStore.tokens, token)
	csrfStore.mu.Unlock()
}

func cleanExpiredTokens() {
	csrfStore.mu.Lock()
	defer csrfStore.mu.Unlock()
	
	now := time.Now()
	for token, expiry := range csrfStore.tokens {
		if now.After(expiry) {
			delete(csrfStore.tokens, token)
		}
	}
}

// Rate limiter for login attempts
type RateLimiter struct {
	attempts map[string][]time.Time
	mu       sync.RWMutex
}

var loginRateLimiter = &RateLimiter{
	attempts: make(map[string][]time.Time),
}

// Check if IP is rate limited (max 5 attempts per minute)
func (rl *RateLimiter) IsRateLimited(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)
	
	// Get attempts for this IP
	attempts := rl.attempts[ip]
	
	// Filter out old attempts
	var recentAttempts []time.Time
	for _, t := range attempts {
		if t.After(cutoff) {
			recentAttempts = append(recentAttempts, t)
		}
	}
	
	rl.attempts[ip] = recentAttempts
	
	// Check if rate limited
	return len(recentAttempts) >= 5
}

// Record a login attempt
func (rl *RateLimiter) RecordAttempt(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	rl.attempts[ip] = append(rl.attempts[ip], time.Now())
}
