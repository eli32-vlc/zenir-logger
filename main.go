package main

import (
	"log"
	"net/http"
	"os"

	"github.com/easonli/zenir/db"
	"github.com/easonli/zenir/handlers"
	"github.com/joho/godotenv"
)

// SecurityHeadersMiddleware adds security headers to all responses
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		
		// Enable XSS protection (for older browsers)
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		
		// Referrer policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		
		// Content Security Policy
		// Note: This is a basic CSP. Adjust based on your needs.
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline'; " + // unsafe-inline needed for inline scripts in templates
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data:; " +
			"font-src 'self'; " +
			"connect-src 'self'; " +
			"frame-ancestors 'none';"
		w.Header().Set("Content-Security-Policy", csp)
		
		next.ServeHTTP(w, r)
	})
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	db.InitDB("zenir.db")

	mux := http.NewServeMux()

	// Static files
	fs := http.FileServer(http.Dir("static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Auth routes
	mux.HandleFunc("/admin/login", handlers.LoginHandler)
	mux.HandleFunc("/admin/logout", handlers.LogoutHandler)

	// Admin routes (protected)
	mux.HandleFunc("/admin", handlers.AuthMiddleware(handlers.AdminDashboardHandler))
	mux.HandleFunc("/admin/create", handlers.AuthMiddleware(handlers.CreateLinkHandler))
	mux.HandleFunc("/admin/stats", handlers.AuthMiddleware(handlers.LinkStatsHandler))
	mux.HandleFunc("/admin/hash", handlers.AuthMiddleware(handlers.HashStatsHandler))
	mux.HandleFunc("/admin/delete", handlers.AuthMiddleware(handlers.DeleteLinkHandler))

	// Public routes
	mux.HandleFunc("/track", handlers.TrackHandler)
	mux.HandleFunc("/", handlers.RootRedirectHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Apply security headers middleware to all routes
	handler := SecurityHeadersMiddleware(mux)

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
