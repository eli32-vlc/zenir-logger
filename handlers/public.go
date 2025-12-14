package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/easonli/zenir/db"
)

func RootRedirectHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		ShortLinkHandler(w, r)
		return
	}
	http.Redirect(w, r, "https://google.com", http.StatusSeeOther)
}

func ShortLinkHandler(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/")
	var target string
	var id int
	err := db.DB.QueryRow("SELECT id, target FROM links WHERE slug = ?", slug).Scan(&id, &target)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Render the intermediate redirect page
	tmpl := template.Must(template.ParseFiles("templates/redirect.html"))
	tmpl.Execute(w, map[string]interface{}{
		"Slug":   slug,
		"Target": target,
		"LinkID": id,
	})
}

type TrackRequest struct {
	LinkID             int     `json:"link_id"`
	ScreenWidth        int     `json:"screen_width"`
	ScreenHeight       int     `json:"screen_height"`
	DevicePixelRatio   float64 `json:"device_pixel_ratio"`
	Language           string  `json:"language"`
	Platform           string  `json:"platform"`
	Fingerprint        string  `json:"fingerprint"`
	FingerprintDetails string  `json:"fingerprint_details"`
	Timezone           string  `json:"timezone"`
	HashCash           string  `json:"hash_cash"`
}

func TrackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TrackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate Hash Cash
	// Challenge: sha256(fingerprint + hash_cash) must start with "0000"
	// This is a simple PoW to prevent spam
	hash := sha256.Sum256([]byte(req.Fingerprint + req.HashCash))
	hashStr := hex.EncodeToString(hash[:])
	if !strings.HasPrefix(hashStr, "0000") {
		log.Printf("Invalid Hash Cash: %s for fingerprint %s", hashStr, req.Fingerprint)
		http.Error(w, "Invalid Hash Cash", http.StatusForbidden)
		return
	}

	ip := r.RemoteAddr
	// Handle X-Forwarded-For if behind a proxy
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = forwarded
	}

	log.Printf("Tracking visit for LinkID: %d, IP: %s", req.LinkID, ip)

	_, err := db.DB.Exec(`INSERT INTO visits 
		(link_id, ip, user_agent, referer, screen_width, screen_height, device_pixel_ratio, language, platform, fingerprint, fingerprint_details, timezone) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.LinkID, ip, r.UserAgent(), r.Referer(), req.ScreenWidth, req.ScreenHeight, req.DevicePixelRatio, req.Language, req.Platform, req.Fingerprint, req.FingerprintDetails, req.Timezone)

	if err != nil {
		log.Printf("Database insert error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
