package handlers

import (
	"html/template"
	"math/rand"
	"net/http"
	"time"

	"github.com/easonli/zenir/db"
)

type Link struct {
	ID        int
	Slug      string
	Target    string
	CreatedAt time.Time
}

type Visit struct {
	ID                 int
	LinkID             int
	IP                 string
	UserAgent          string
	Referer            string
	ScreenWidth        int
	ScreenHeight       int
	DevicePixelRatio   float64
	Language           string
	Platform           string
	Fingerprint        string
	FingerprintDetails string
	Timezone           string
	Timestamp          time.Time
}

type PageData struct {
	Authenticated bool
	Data          interface{}
}

func AdminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query("SELECT id, slug, target, created_at FROM links ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var links []Link
	for rows.Next() {
		var l Link
		if err := rows.Scan(&l.ID, &l.Slug, &l.Target, &l.CreatedAt); err != nil {
			continue
		}
		links = append(links, l)
	}

	tmpl := template.Must(template.ParseFiles("templates/layout.html", "templates/admin.html"))
	tmpl.Execute(w, PageData{
		Authenticated: true,
		Data:          links,
	})
}

func CreateLinkHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	target := r.FormValue("target")
	slug := r.FormValue("slug")

	if slug == "" {
		slug = generateSlug(6)
	}

	_, err := db.DB.Exec("INSERT INTO links (slug, target) VALUES (?, ?)", slug, target)
	if err != nil {
		http.Error(w, "Slug already exists or database error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func LinkStatsHandler(w http.ResponseWriter, r *http.Request) {
	slug := r.URL.Query().Get("slug")
	var linkID int
	err := db.DB.QueryRow("SELECT id FROM links WHERE slug = ?", slug).Scan(&linkID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	rows, err := db.DB.Query("SELECT id, link_id, ip, user_agent, referer, screen_width, screen_height, device_pixel_ratio, language, platform, fingerprint, COALESCE(fingerprint_details, ''), COALESCE(timezone, ''), timestamp FROM visits WHERE link_id = ? ORDER BY timestamp DESC", linkID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var visits []Visit
	for rows.Next() {
		var v Visit
		if err := rows.Scan(&v.ID, &v.LinkID, &v.IP, &v.UserAgent, &v.Referer, &v.ScreenWidth, &v.ScreenHeight, &v.DevicePixelRatio, &v.Language, &v.Platform, &v.Fingerprint, &v.FingerprintDetails, &v.Timezone, &v.Timestamp); err != nil {
			// log.Println("Scan error:", err)
			continue
		}
		visits = append(visits, v)
	}

	tmpl := template.Must(template.ParseFiles("templates/layout.html", "templates/stats.html"))
	tmpl.Execute(w, PageData{
		Authenticated: true,
		Data: map[string]interface{}{
			"Slug":   slug,
			"Visits": visits,
		},
	})
}

func HashStatsHandler(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Query().Get("hash")
	
	rows, err := db.DB.Query("SELECT id, link_id, ip, user_agent, referer, screen_width, screen_height, device_pixel_ratio, language, platform, fingerprint, COALESCE(fingerprint_details, ''), COALESCE(timezone, ''), timestamp FROM visits WHERE fingerprint = ? ORDER BY timestamp DESC", hash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var visits []Visit
	for rows.Next() {
		var v Visit
		if err := rows.Scan(&v.ID, &v.LinkID, &v.IP, &v.UserAgent, &v.Referer, &v.ScreenWidth, &v.ScreenHeight, &v.DevicePixelRatio, &v.Language, &v.Platform, &v.Fingerprint, &v.FingerprintDetails, &v.Timezone, &v.Timestamp); err != nil {
			continue
		}
		visits = append(visits, v)
	}

	tmpl := template.Must(template.ParseFiles("templates/layout.html", "templates/hash.html"))
	tmpl.Execute(w, PageData{
		Authenticated: true,
		Data: map[string]interface{}{
			"Hash":   hash,
			"Visits": visits,
		},
	})
}

func DeleteLinkHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.FormValue("id")
	if id == "" {
		http.Error(w, "Missing link ID", http.StatusBadRequest)
		return
	}

	// Start transaction
	tx, err := db.DB.Begin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Delete visits first (foreign key constraint)
	_, err = tx.Exec("DELETE FROM visits WHERE link_id = ?", id)
	if err != nil {
		tx.Rollback()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Delete link
	_, err = tx.Exec("DELETE FROM links WHERE id = ?", id)
	if err != nil {
		tx.Rollback()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func generateSlug(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
