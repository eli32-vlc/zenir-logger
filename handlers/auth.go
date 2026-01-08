package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/sessions"
)

var store *sessions.CookieStore

// Rate limiting for login attempts
type loginAttempt struct {
	count      int
	lastAttempt time.Time
}

var (
	loginAttempts = make(map[string]*loginAttempt)
	loginMutex    sync.RWMutex
)

const (
	maxLoginAttempts = 5
	loginLockoutTime = 15 * time.Minute
)

func init() {
	sessionKey := os.Getenv("SESSION_KEY")
	if sessionKey == "" {
		log.Println("WARNING: SESSION_KEY not set in environment. Generating a random key.")
		log.Println("WARNING: Sessions will be invalidated on server restart.")
		log.Println("WARNING: Please set SESSION_KEY in your .env file for production use.")
		
		// Generate a secure random session key
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Fatal("Failed to generate random session key:", err)
		}
		sessionKey = base64.StdEncoding.EncodeToString(key)
	}
	store = sessions.NewCookieStore([]byte(sessionKey))
	
	// Set secure cookie options
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   os.Getenv("SECURE_COOKIES") == "true", // Enable in production with HTTPS
		SameSite: http.SameSiteStrictMode,
	}
	
	// Clean up old login attempts every hour
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			cleanupLoginAttempts()
		}
	}()
}

func cleanupLoginAttempts() {
	loginMutex.Lock()
	defer loginMutex.Unlock()
	
	now := time.Now()
	for ip, attempt := range loginAttempts {
		if now.Sub(attempt.lastAttempt) > loginLockoutTime {
			delete(loginAttempts, ip)
		}
	}
}

func checkRateLimit(ip string) bool {
	loginMutex.RLock()
	attempt, exists := loginAttempts[ip]
	loginMutex.RUnlock()
	
	if !exists {
		return true
	}
	
	if time.Since(attempt.lastAttempt) > loginLockoutTime {
		return true
	}
	
	return attempt.count < maxLoginAttempts
}

func recordLoginAttempt(ip string, success bool) {
	loginMutex.Lock()
	defer loginMutex.Unlock()
	
	if success {
		delete(loginAttempts, ip)
		return
	}
	
	attempt, exists := loginAttempts[ip]
	if !exists {
		loginAttempts[ip] = &loginAttempt{
			count:      1,
			lastAttempt: time.Now(),
		}
		return
	}
	
	if time.Since(attempt.lastAttempt) > loginLockoutTime {
		attempt.count = 1
	} else {
		attempt.count++
	}
	attempt.lastAttempt = time.Now()
}

// Generate CSRF token
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// Get or create CSRF token for session
func getCSRFToken(session *sessions.Session) (string, error) {
	if token, ok := session.Values["csrf_token"].(string); ok && token != "" {
		return token, nil
	}
	
	token, err := generateCSRFToken()
	if err != nil {
		return "", err
	}
	
	session.Values["csrf_token"] = token
	return token, nil
}

// GetCSRFTokenForRequest - Helper to get CSRF token from request
func GetCSRFTokenForRequest(r *http.Request, w http.ResponseWriter) (string, error) {
	session, _ := store.Get(r, "session-name")
	token, err := getCSRFToken(session)
	if err != nil {
		return "", err
	}
	session.Save(r, w)
	return token, nil
}

// Validate CSRF token
func validateCSRFToken(r *http.Request, session *sessions.Session) bool {
	sessionToken, ok := session.Values["csrf_token"].(string)
	if !ok || sessionToken == "" {
		return false
	}
	
	formToken := r.FormValue("csrf_token")
	return formToken == sessionToken
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	
	if r.Method == "GET" {
		csrfToken, err := getCSRFToken(session)
		if err != nil {
			log.Printf("Failed to generate CSRF token: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		session.Save(r, w)
		
		tmpl := template.Must(template.ParseFiles("templates/layout.html", "templates/login.html"))
		tmpl.Execute(w, PageData{
			Authenticated: false,
			Data: map[string]string{
				"CSRFToken": csrfToken,
			},
		})
		return
	}

	// Validate CSRF token for POST requests
	if !validateCSRFToken(r, session) {
		log.Printf("CSRF token validation failed")
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Get client IP for rate limiting
	ip := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// Take the first IP in the X-Forwarded-For chain
		ip = forwarded
		if idx := len(ip); idx > 0 {
			for i, c := range ip {
				if c == ',' {
					idx = i
					break
				}
			}
			ip = ip[:idx]
		}
	}

	// Check rate limit
	if !checkRateLimit(ip) {
		http.Error(w, "Too many login attempts. Please try again later.", http.StatusTooManyRequests)
		log.Printf("Rate limit exceeded for IP: %s", ip)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == os.Getenv("ADMIN_USER") && password == os.Getenv("ADMIN_PASS") {
		recordLoginAttempt(ip, true)
		session, _ := store.Get(r, "session-name")
		session.Values["authenticated"] = true
		session.Save(r, w)
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	recordLoginAttempt(ip, false)
	log.Printf("Failed login attempt from IP: %s", ip)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = false
	session.Save(r, w)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		
		// Validate CSRF token for state-changing requests
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
			if !validateCSRFToken(r, session) {
				log.Printf("CSRF token validation failed for %s %s", r.Method, r.URL.Path)
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		
		next(w, r)
	}
}
