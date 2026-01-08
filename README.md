# Zenir Logger V2

A powerful, self-hosted URL shortener and logger with advanced fingerprinting capabilities. Built with Go and SQLite, packaged with a clean, terminal-styled interface.

## Features

### 🔗 URL Management
-   **Short Links**: Create custom slugs or generate random ones.
-   **Intermediate Redirect**: Visitors land on a loading page that executes fingerprinting scripts before redirecting to the destination.
-   **Management**: Delete unwanted links and their associated data.

### 🕵️ Advanced Tracking & Analytics
-   **Comprehensive Data Collection**: Tracks IP, User Agent, Referer, Language, and Platform.
-   **Device Fingerprinting**: Collects screen dimensions, pixel ratio, and more to generate a unique visitor fingerprint.
-   **Hash Cash Validation**: Implements a Proof-of-Work challenge (`sha256(fingerprint + hash_cash)`) to prevent bot spam on the tracking endpoint.
-   **Fingerprint Correlation**: View all visits associated with a specific browser fingerprint hash to track users across different links.

### 🛡️ Admin Panel
-   **Secure Login**: Simple environment-based username and password authentication.
-   **Dashboard**: View all active links and their creation dates.
-   **Stats View**: Detailed breakdown of every visit for a specific link.

## Getting Started

### Prerequisites
-   Go 1.22+
-   Git

### Installation

1.  **Clone the repository**
    ```bash
    git clone https://github.com/eli32-vlc/zenir-logger.git
    cd zenir
    ```

2.  **Configuration**
    Create a `.env` file in the root directory:
    ```bash
    PORT=8080
    SESSION_KEY=$(openssl rand -base64 32)  # Generate a secure random key
    ADMIN_USER=admin
    ADMIN_PASS=your-strong-password-here
    SECURE_COOKIES=true  # Enable in production with HTTPS
    ```
    
    **⚠️ Security Note**: Always use a strong, randomly generated `SESSION_KEY` and strong admin credentials in production.

3.  **Build and Run**
    ```bash
    go build -o zenir main.go
    ./zenir
    ```
    Or run directly:
    ```bash
    go run main.go
    ```

4.  **Access**
    -   Public Redirect: `http://localhost:8080/<slug>`
    -   Admin Panel: `http://localhost:8080/admin/login`

## Architecture

-   **Backend**: Go (Golang)
-   **Database**: SQLite (`zenir.db`)
-   **Frontend**: HTML Templates with [Terminal.css](https://terminalcss.xyz/) styling.
-   **Tracking**: API endpoint `/track` accepts JSON payload from client-side JS.

## API Endpoints

### Public
-   `GET /<slug>`: Resolves link and serves tracking page.
-   `POST /track`: Receives analytics data. Requires valid `hash_cash`.

### Admin (Protected)
-   `GET /admin`: Dashboard.
-   `POST /admin/create`: Create link.
-   `GET /admin/stats`: View link stats.
-   `GET /admin/hash`: View fingerprint history.
-   `POST /admin/delete`: Delete link.

## License

Copyright Zenith Rifle 2025.

## Security

For information about security vulnerabilities and fixes, see [SECURITY.md](SECURITY.md).

**Key Security Features:**
- ✅ CSRF protection on all forms
- ✅ Rate limiting on login attempts (5 attempts per 15 minutes)
- ✅ Secure session management with HttpOnly cookies
- ✅ URL validation to prevent XSS via malicious URLs
- ✅ Content Security Policy headers
- ✅ IP spoofing prevention
- ✅ Cryptographically secure random slug generation
