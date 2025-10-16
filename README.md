# GoProxy

<img src="logo.svg" width="100">

A lightweight, feature-rich HTTPS reverse proxy server written in Go, with automatic SSL certificate management and multi-domain support.

## Features

- 🔒 Automatic SSL/TLS certificate management via Let's Encrypt
- 🌐 Multi-domain support
- 🔄 Easy reverse proxy configuration
- 🔌 WebSocket support
- 📁 Static file serving
- 📝 Detailed logging
- ⚡ High performance with Go's concurrency
- 🗜️ Intelligent content compression (gzip)
- 🔑 Basic authentication support per domain
- 🔄 Domain-level redirects
- 🎯 Custom fallback paths for SPAs (works with both static serving and proxy)

## Quick Start

1. Install using Go:
```bash
go install github.com/d0rc/goproxy@latest
```

2. Create a configuration file `config.txt`:
```txt
# Domain 1 configuration
domain=example.com
static_dir=/var/www/example
proxy=/api http://localhost:8080
proxy=/socket ws://localhost:8081

# Domain 2 configuration
domain=another.example.com
static_dir=/var/www/another
proxy=/backend http://localhost:9000
```

3. Run the server:
```bash
goproxy -config config.txt
```

## Configuration

The configuration file uses a simple key-value format:

- `domain`: Specifies the domain name (required for each domain block)
- `static_dir`: Directory for serving static files
- `proxy`: Format is `proxy=<path> <target_url>` where:
    - `path`: URL path to match
    - `target_url`: Destination URL to proxy (supports both HTTP and WebSocket)
- `auth`: Format is `auth=<username> <password>` for Basic Authentication
- `fallback_path`: Path to serve when a file is not found (e.g., `/index.html` for SPA routing). Works with both static file serving and proxy configurations
- `redirect`: Redirects all requests to the specified domain while preserving paths and query parameters

The proxy automatically handles content compression (gzip) for appropriate content types including:
- Text files (HTML, CSS, JavaScript, etc.)
- JSON and XML responses
- Form-encoded data
- While skipping already-compressed content (images, videos, archives)

### Example Configuration

```txt
# Main website with static files and API proxy
domain=example.com
static_dir=/var/www/main
proxy=/api https://api.internal:8080
proxy=/ws ws://websocket.internal:8081
fallback_path=/index.html

# SPA with full proxy (NEW: fallback_path now works with proxy)
domain=spa.example.com
static_dir=/var/www/spa-static
proxy=/ http://backend:3000
fallback_path=/index.html

# Redirect www subdomain to naked domain
# A request to www.example.com/blog?page=2 will redirect to example.com/blog?page=2
domain=www.example.com
redirect=example.com

# Admin panel
domain=admin.example.com
static_dir=/var/www/admin
auth=adminuser strongpassword

# Complete example showing all features
domain=example.com
static_dir=/var/www/main
proxy=/api https://api.internal:8080
proxy=/ws ws://websocket.internal:8081
fallback_path=/index.html
auth=admin secretpassword
redirect=example.com   # Optional redirect target
```

## Features in Detail

### SSL/TLS Certificate Management

- Automatic certificate acquisition and renewal via Let's Encrypt
- Certificates are cached locally in the `certs` directory
- Automatic renewal 30 days before expiration
- HTTP-01 challenge support

### Reverse Proxy Features

- Path-based routing
- WebSocket support with automatic protocol upgrade
- Error handling and logging
- Request/response header modification
- Connection state monitoring
- **SPA fallback support**: When proxying returns 404, can serve a fallback file (e.g., `index.html`) for client-side routing

### SPA (Single Page Application) Support

GoProxy provides comprehensive SPA support through the `fallback_path` configuration:

#### How It Works

1. **With Static Files Only**: When a requested file doesn't exist, serves the fallback file
2. **With Proxy**: When the proxied backend returns 404, intelligently determines if it should serve the fallback:
   - Navigation requests (Accept: text/html) → Serve fallback
   - API requests (Accept: application/json, paths with /api/) → Return 404
   - Static assets (.js, .css, images, etc.) → Return 404

#### Configuration for SPAs

```txt
# Pure static SPA
domain=myapp.com
static_dir=/var/www/app
fallback_path=/index.html

# SPA with backend proxy
domain=myapp.com
static_dir=/var/www/app
proxy=/ http://backend:3000
fallback_path=/index.html
```

This allows SPAs to handle client-side routing while still properly returning 404s for missing API endpoints and static assets.

### Static File Serving & SPA Support

- Serve static files for each domain
- Automatic index file serving
- Clean URLs without file extensions
- SPA fallback support for client-side routing
- Intelligent detection of navigation vs. asset requests
- Works with both static serving and proxy configurations

### Logging

- Detailed request logging with timing
- Certificate management logging
- Connection state changes
- Error logging with stack traces

## Architecture

```mermaid
graph TD
    A[Client Request] --> B[HTTP/HTTPS Server]
    B --> C{Domain Router}
    C --> D[Static File Server]
    C --> E[Reverse Proxy]
    C --> F[WebSocket Proxy]
    E --> G[Backend Services]
    F --> H[WebSocket Services]
```

## Building from Source

```bash
git clone https://github.com/d0rc/goproxy
cd goproxy
go build
```

### Prerequisites

- Go 1.16 or later
- External dependencies:
    - github.com/gorilla/mux
    - github.com/gorilla/websocket
    - golang.org/x/crypto/acme
    - golang.org/x/crypto/acme/autocert

## Production Deployment

1. Set up proper system user and permissions
2. Configure systemd service (recommended)
3. Set up log rotation
4. Configure firewall rules (ports 80 and 443)
5. Update email address in certificate manager configuration

### Example Systemd Service

```ini
[Unit]
Description=GoProxy HTTPS Reverse Proxy
After=network.target

[Service]
Type=simple
User=goproxy
ExecStart=/usr/local/bin/goproxy -config /etc/goproxy/config.txt
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

## Security Considerations

- Regularly update the software and dependencies
- Monitor certificate renewal status
- Use proper file permissions for certificates and configuration
- Configure appropriate security headers
- Consider rate limiting for production use
- Keep backup of certificates and configuration

## Resources

- [GoProxy: Hosting Static and Dynamic Sites with Ease](https://legacysupportteam.com/blog/goproxy-hosting-static-dynamic-sites/) - A comprehensive guide on using GoProxy for static and dynamic site hosting
- [GitHub Repository](https://github.com/d0rc/goproxy)

## Contributing

Contributions are welcome! Please feel free to submit pull requests. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The Go team for the excellent standard library
- Gorilla toolkit developers
- Let's Encrypt for providing free SSL certificates

## Command Line Options

The following command-line options are available:
- `-config`: Path to the configuration file (default: "config.txt")
- `-account-email`: Email address for Let's Encrypt registration