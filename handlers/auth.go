package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
)

var store *sessions.CookieStore

func init() {
	sessionKey := os.Getenv("SESSION_KEY")
	if sessionKey == "" {
		// Generate a random session key if not provided
		key := make([]byte, 32)
		rand.Read(key)
		sessionKey = base64.StdEncoding.EncodeToString(key)
	}
	store = sessions.NewCookieStore([]byte(sessionKey))
	
	// Configure session options for security
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600 * 8, // 8 hours
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Generate CSRF token for the form
		csrfToken := GenerateCSRFToken()
		
		tmpl := template.Must(template.ParseFiles("templates/layout.html", "templates/login.html"))
		tmpl.Execute(w, PageData{
			Authenticated: false,
			Data: map[string]interface{}{
				"CSRFToken": csrfToken,
			},
		})
		return
	}

	// Get client IP for rate limiting
	ip := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = forwarded
	}

	// Check rate limiting
	if loginRateLimiter.IsRateLimited(ip) {
		http.Error(w, "Too many login attempts. Please try again later.", http.StatusTooManyRequests)
		return
	}

	// Record attempt
	loginRateLimiter.RecordAttempt(ip)

	// Validate CSRF token
	csrfToken := r.FormValue("csrf_token")
	if !ValidateCSRFToken(csrfToken) {
		http.Error(w, "Invalid or expired CSRF token", http.StatusForbidden)
		return
	}
	ConsumeCSRFToken(csrfToken)

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == os.Getenv("ADMIN_USER") && password == os.Getenv("ADMIN_PASS") {
		session, _ := store.Get(r, "session-name")
		session.Values["authenticated"] = true
		session.Save(r, w)
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

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
		next(w, r)
	}
}
