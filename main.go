package main

import (
	"log"
	"net/http"
	"os"

	"github.com/easonli/zenir/db"
	"github.com/easonli/zenir/handlers"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	db.InitDB("zenir.db")

	// Static files
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Auth routes
	http.HandleFunc("/admin/login", handlers.LoginHandler)
	http.HandleFunc("/admin/logout", handlers.LogoutHandler)

	// Admin routes (protected)
	http.HandleFunc("/admin", handlers.AuthMiddleware(handlers.AdminDashboardHandler))
	http.HandleFunc("/admin/create", handlers.AuthMiddleware(handlers.CreateLinkHandler))
	http.HandleFunc("/admin/stats", handlers.AuthMiddleware(handlers.LinkStatsHandler))
	http.HandleFunc("/admin/hash", handlers.AuthMiddleware(handlers.HashStatsHandler))
	http.HandleFunc("/admin/delete", handlers.AuthMiddleware(handlers.DeleteLinkHandler))

	// Public routes
	http.HandleFunc("/track", handlers.TrackHandler)
	http.HandleFunc("/", handlers.RootRedirectHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
