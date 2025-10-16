package main

// -build-me-for: linux
import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"compress/gzip"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var (
	disableCompression = flag.Bool("disable-compression", false, "Disable gzip compression entirely")
	requestCounter     uint64 // Atomic counter for request IDs
)

// RequestIDKey is the context key for request IDs
type RequestIDKey struct{}

//go:embed mime.types
var mimeTypesData string

type DomainConfig struct {
	StaticDir    string
	ProxyURLs    map[string]string
	FallbackPath string
	RedirectTo   string
	BasicAuth    struct {
		Username string
		Password string
	}
}

var (
	domains        map[string]DomainConfig
	certManager    *autocert.Manager
	fallbackCache  = make(map[string][]byte) // Cache for fallback content
	fallbackMutex  sync.RWMutex              // Mutex for fallback cache
)

// compressResponseWriter is a response writer that decides whether to compress
// the response based on the Content-Type header. It also handles SSE streaming.
type compressResponseWriter struct {
	http.ResponseWriter
	gzWriter    *gzip.Writer
	wroteHeader bool
	doCompress  bool
	isStreaming bool
	wroteBody   bool // Track if we actually wrote any body data
	statusCode  int  // Track the status code
	requestID   uint64
}

func (w *compressResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.statusCode = status

	contentType := w.Header().Get("Content-Type")
	contentEncoding := w.Header().Get("Content-Encoding")

	// Check if this is a streaming response
	// Only mark as streaming for actual streaming content types
	w.isStreaming = strings.Contains(contentType, "text/event-stream")

	if w.isStreaming {
		log.Printf("[REQ-%d] Detected streaming response (Content-Type: %s)", w.requestID, contentType)
	}

	// Check if this status code allows a body
	statusAllowsBody := status != http.StatusNoContent &&
		status != http.StatusNotModified &&
		status != http.StatusContinue &&
		status != http.StatusSwitchingProtocols &&
		status != http.StatusProcessing &&
		status != http.StatusEarlyHints

	// Do not compress for SSE, streaming responses, status codes without body, or if already compressed
	if !statusAllowsBody || w.isStreaming || contentEncoding != "" {
		w.doCompress = false
		w.ResponseWriter.WriteHeader(status)
		return
	}

	// Check if we should compress based on content type
	if shouldCompress(contentType) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length")
		// Explicitly set chunked encoding when compressing
		w.Header().Set("Transfer-Encoding", "chunked")
		w.doCompress = true
		// Only set Vary header when actually compressing
		existing := w.Header().Get("Vary")
		if existing != "" && !strings.Contains(existing, "Accept-Encoding") {
			w.Header().Set("Vary", existing+", Accept-Encoding")
		} else if existing == "" {
			w.Header().Set("Vary", "Accept-Encoding")
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *compressResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	// Don't write anything if the status code doesn't allow a body
	if len(b) == 0 {
		return 0, nil
	}

	w.wroteBody = true

	var n int
	var err error

	if w.doCompress && w.gzWriter != nil {
		n, err = w.gzWriter.Write(b)
		if err == nil {
			// Always flush for streaming responses
			if w.isStreaming {
				w.gzWriter.Flush()
				if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
					flusher.Flush()
				}
			} else if n > 0 && n < 1024 {
				// For small writes, flush immediately to prevent buffering issues
				// This helps with mobile browsers that expect immediate data
				w.gzWriter.Flush()
			}
		}
	} else {
		n, err = w.ResponseWriter.Write(b)
		// Flush for streaming responses
		if err == nil && w.isStreaming {
			if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	}

	if err != nil && w.isStreaming {
		log.Printf("[REQ-%d] Write error for streaming response: %v", w.requestID, err)
	}

	return n, err
}

func (w *compressResponseWriter) Flush() {
	// Always flush the gzip writer first if compressing
	if w.doCompress && w.gzWriter != nil {
		w.gzWriter.Flush()
	}
	// Then flush the underlying response writer
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *compressResponseWriter) Close() error {
	// This method is now primarily called from compressionMiddleware
	// The middleware handles the actual flush and close sequence
	// This is kept for compatibility but the main work is done in the middleware
	return nil
}

var email = flag.String("account-email", "info@d-tech.ge", "Put your e-mail here for SSL account registration:)")

func main() {
	// Parse command-line flags
	configFile := flag.String("config", "config.txt", "Path to the configuration file")
	flag.Parse()

	// Load configuration
	err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	// Load custom MIME types
	loadMimeTypes()

	log.Printf("Starting with config at %s and account email %s\n", *configFile, *email)

	// Initialize autocert manager
	certManager = createCertManager(*email, getDomainNames())

	// Create the main router
	mainRouter := mux.NewRouter()

	// Add request ID middleware first
	mainRouter.Use(requestIDMiddleware)
	// Add compression middleware BEFORE logging middleware
	mainRouter.Use(compressionMiddleware)
	mainRouter.Use(loggingMiddleware)

	// Set up routes for each domain
	for domain, config := range domains {
		router := mainRouter.Host(domain).Subrouter()

		// Handle redirect first, if configured
		if config.RedirectTo != "" {
			log.Printf("Setting up redirect for domain %s to %s", domain, config.RedirectTo)
			router.PathPrefix("/").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				newURL := "https://" + config.RedirectTo + r.URL.Path
				if r.URL.RawQuery != "" {
					newURL += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, newURL, http.StatusMovedPermanently)
			}))
			continue // Skip other handlers for this domain
		}

		// Add basic auth middleware for this domain
		router.Use(func(next http.Handler) http.Handler {
			return basicAuthMiddleware(next, config)
		})

		// Set up proxy routes FIRST
		for path, targetURL := range config.ProxyURLs {
			log.Printf("Setting up proxy route for domain %s: %s -> %s", domain, path, targetURL)
			// Check if this is a catch-all proxy and we have a fallback configured
			if path == "/" && config.FallbackPath != "" {
				// Create a special handler that combines proxy with fallback
				// Works with or without static_dir
				if config.StaticDir != "" {
					// Use static file fallback
					proxy := createProxyWithStaticFallback(targetURL, config.StaticDir, config.FallbackPath)
					router.PathPrefix(path).Handler(proxy)
				} else {
					// Use proxy-based fallback (fetch from backend)
					proxy := createProxyWithProxyFallback(targetURL, config.FallbackPath)
					router.PathPrefix(path).Handler(proxy)
				}
			} else {
				proxy := createReverseProxy(targetURL)
				router.PathPrefix(path).Handler(proxy)
			}
		}

		// Set up static file serving LAST
		if config.StaticDir != "" {
			if config.FallbackPath == "" {
				log.Printf("Setting up static file serving for domain %s from directory: %s", domain, config.StaticDir)
				fs := http.FileServer(http.Dir(config.StaticDir))
				router.PathPrefix("/").Handler(http.StripPrefix("/", fs))
			} else {
				log.Printf("Setting up static file serving for domain %s from directory: %s with fallback at %s", domain, config.StaticDir, config.FallbackPath)
				// Use the custom file server handler with the configured fallback path
				fs := customFileServer(http.Dir(config.StaticDir), config.FallbackPath)
				router.PathPrefix("/").Handler(http.StripPrefix("/", fs))
			}
		}
	}

	// Set up the TLS configuration
	tlsConfig := &tls.Config{
		GetCertificate: loggedGetCertificate,
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
	}

	// Set up the HTTPS server with proper timeouts
	server := &http.Server{
		Addr:      ":https",
		Handler:   mainRouter,
		TLSConfig: tlsConfig,
		ErrorLog:  log.New(os.Stderr, "HTTPS Server Error: ", log.Ldate|log.Ltime|log.Lshortfile),
		ConnState: logConnState,
		// Timeouts for better connection management
		ReadTimeout:       600 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      600 * time.Second,
		IdleTimeout:       600 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	// Start certificate management
	go manageCertificates()

	// Start HTTP-01 challenge server with timeouts
	go func() {
		log.Println("Starting HTTP server for ACME challenges on :80")
		httpServer := &http.Server{
			Addr:              ":http",
			Handler:           wrapHandlerWithLogging(certManager.HTTPHandler(nil)),
			ConnState:         logConnState,
			ReadTimeout:       10 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    1 << 20, // 1 MB
		}
		if err := httpServer.ListenAndServe(); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Start the HTTPS server
	log.Println("Starting HTTPS server on :443")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func loadMimeTypes() {
	scanner := bufio.NewScanner(strings.NewReader(mimeTypesData))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 2 {
			if err := mime.AddExtensionType(parts[0], parts[1]); err != nil {
				log.Printf("Warning: Could not add MIME type for %s: %v", parts[0], err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Warning: Error reading embedded MIME types: %v", err)
	}
}

func loadConfig(configFile string) error {
	domains = make(map[string]DomainConfig)

	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	var currentDomain string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid config line: %s", line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "domain":
			currentDomain = value
			domains[currentDomain] = DomainConfig{
				ProxyURLs: make(map[string]string),
			}
		case "auth":
			authParts := strings.SplitN(value, " ", 2)
			if len(authParts) != 2 {
				return fmt.Errorf("invalid auth config: %s", value)
			}
			config := domains[currentDomain]
			config.BasicAuth.Username = authParts[0]
			config.BasicAuth.Password = authParts[1]
			domains[currentDomain] = config
		case "static_dir":
			config := domains[currentDomain]
			config.StaticDir = value
			domains[currentDomain] = config
		case "proxy":
			proxyParts := strings.SplitN(value, " ", 2)
			if len(proxyParts) != 2 {
				return fmt.Errorf("invalid proxy config: %s", value)
			}
			config := domains[currentDomain]
			config.ProxyURLs[proxyParts[0]] = proxyParts[1]
			domains[currentDomain] = config
		case "fallback_path":
			config := domains[currentDomain]
			config.FallbackPath = value
			domains[currentDomain] = config
		case "redirect":
			config := domains[currentDomain]
			config.RedirectTo = value
			domains[currentDomain] = config
		default:
			return fmt.Errorf("unknown config key: %s", key)
		}
	}

	return nil
}

func getDomainNames() []string {
	var names []string
	for domain := range domains {
		names = append(names, domain)
	}
	return names
}

func createCertManager(email string, domains []string) *autocert.Manager {
	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
		Cache:      autocert.DirCache("certs"),
		Email:      email,
	}
}

// flushingResponseWriter wraps http.ResponseWriter to ensure proper flushing
type flushingResponseWriter struct {
	http.ResponseWriter
	flusher http.Flusher
}

func (w *flushingResponseWriter) Flush() {
	if w.flusher != nil {
		w.flusher.Flush()
	}
}

// singleJoiningSlash joins two URL paths with a single slash
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func createReverseProxy(targetURL string) http.Handler {
	return createReverseProxyWithFallback(targetURL, "")
}

func createReverseProxyWithFallback(targetURL string, fallbackPath string) http.Handler {
	log.Printf("Creating reverse proxy for url: %s", targetURL)
	if fallbackPath != "" {
		log.Printf("  with SPA fallback to: %s", fallbackPath)
	}
	target, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("Error parsing proxy URL: %v", err)
	}

	// Create the reverse proxy with custom transport for better timeout control
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   600 * time.Second,
			KeepAlive: 600 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 600 * time.Second,
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
			if target.RawQuery == "" || req.URL.RawQuery == "" {
				req.URL.RawQuery = target.RawQuery + req.URL.RawQuery
			} else {
				req.URL.RawQuery = target.RawQuery + "&" + req.URL.RawQuery
			}
			if _, ok := req.Header["User-Agent"]; !ok {
				// explicitly disable User-Agent so it's not set to default value
				req.Header.Set("User-Agent", "")
			}
		},
		Transport: transport,
		// Enable immediate flushing for streaming responses
		FlushInterval: 100 * time.Millisecond,
	}

	// Customize the director
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Get request ID from context
		requestID := uint64(0)
		if id, ok := req.Context().Value(RequestIDKey{}).(uint64); ok {
			requestID = id
		}

		// Get the client IP
		clientIP := req.RemoteAddr
		if colon := strings.LastIndex(clientIP, ":"); colon != -1 {
			clientIP = clientIP[:colon]
		}

		// Set headers to be forwarded
		req.Header.Set("X-Real-IP", clientIP)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Request-ID", fmt.Sprintf("%d", requestID))

		// Get existing X-Forwarded-For header
		forwardedFor := req.Header.Get("X-Forwarded-For")
		if forwardedFor != "" {
			// Append the client IP to the existing X-Forwarded-For value
			req.Header.Set("X-Forwarded-For", forwardedFor+", "+clientIP)
		} else {
			// Set new X-Forwarded-For header with client IP
			req.Header.Set("X-Forwarded-For", clientIP)
		}

		log.Printf("[REQ-%d] Proxying request to %s%s", requestID, target.Host, req.URL.Path)
	}

	// Custom ModifyResponse to handle streaming and SPA fallback
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Get request ID from the request header we set
		requestID := uint64(0)
		if idStr := resp.Request.Header.Get("X-Request-ID"); idStr != "" {
			fmt.Sscanf(idStr, "%d", &requestID)
		}

		// Check if this is a streaming response
		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "text/event-stream") ||
			strings.Contains(contentType, "application/octet-stream") {
			log.Printf("[REQ-%d] Proxy received streaming response (Content-Type: %s, Status: %d)",
				requestID, contentType, resp.StatusCode)
			// Ensure proper headers for streaming
			resp.Header.Set("Cache-Control", "no-cache")
			resp.Header.Set("Connection", "keep-alive")
			resp.Header.Del("Content-Length")
			resp.Header.Set("Transfer-Encoding", "chunked")
			resp.Header.Set("X-Accel-Buffering", "no") // Disable nginx buffering if present
		}

		// Handle SPA fallback for 404 responses
		if fallbackPath != "" && resp.StatusCode == http.StatusNotFound {
			// Check if this is likely a navigation request (not an API or asset request)
			if shouldFallbackToSPA(resp.Request) {
				log.Printf("[REQ-%d] Proxy 404 detected, checking for SPA fallback", requestID)
				
				// We can't directly serve a file here, but we can modify the response
				// to indicate that fallback should be served
				resp.Header.Set("X-Proxy-Fallback", fallbackPath)
			}
		}

		return nil
	}

	// Add error handling
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		requestID := uint64(0)
		if id, ok := r.Context().Value(RequestIDKey{}).(uint64); ok {
			requestID = id
		}
		log.Printf("[REQ-%d] Proxy error for %s: %v", requestID, r.URL.Path, err)
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "Proxy error: %v", err)
	}

	// Wrap the proxy to ensure proper flushing
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the ResponseWriter supports flushing
		if flusher, ok := w.(http.Flusher); ok {
			fw := &flushingResponseWriter{
				ResponseWriter: w,
				flusher:        flusher,
			}
			proxy.ServeHTTP(fw, r)
		} else {
			proxy.ServeHTTP(w, r)
		}
	})
}

func customFileServer(root http.FileSystem, fallback string) http.Handler {
	fs := http.FileServer(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to serve the requested file
		path := r.URL.Path
		f, err := root.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				// If the file doesn't exist, serve the fallback file
				r.URL.Path = fallback
			}
		} else {
			// Close the file if it was successfully opened
			f.Close()
		}
		fs.ServeHTTP(w, r)
	})
}

// shouldFallbackToSPA determines if a 404 response should trigger SPA fallback
func shouldFallbackToSPA(req *http.Request) bool {
	// Get request ID for logging
	requestID := uint64(0)
	if id, ok := req.Context().Value(RequestIDKey{}).(uint64); ok {
		requestID = id
	}
	
	// Get the Accept header
	accept := req.Header.Get("Accept")
	log.Printf("[REQ-%d] shouldFallbackToSPA: Path=%s, Accept=%s", requestID, req.URL.Path, accept)
	
	// Check if this is likely an API request
	if strings.Contains(accept, "application/json") {
		log.Printf("[REQ-%d] shouldFallbackToSPA: NO - Accept contains application/json", requestID)
		return false
	}
	if strings.Contains(req.URL.Path, "/api/") || strings.Contains(req.URL.Path, "/ws/") || strings.Contains(req.URL.Path, "/websocket") {
		log.Printf("[REQ-%d] shouldFallbackToSPA: NO - Path contains API/WS indicators", requestID)
		return false
	}
	
	// Check if this is a static asset request
	ext := strings.ToLower(getFileExtension(req.URL.Path))
	if ext != "" {
		log.Printf("[REQ-%d] shouldFallbackToSPA: File extension detected: %s", requestID, ext)
	}
	
	staticExtensions := map[string]bool{
		".js":    true,
		".css":   true,
		".png":   true,
		".jpg":   true,
		".jpeg":  true,
		".gif":   true,
		".svg":   true,
		".ico":   true,
		".woff":  true,
		".woff2": true,
		".ttf":   true,
		".eot":   true,
		".map":   true,
		".json":  true,
		".xml":   true,
		".txt":   true,
		".webp":  true,
		".avif":  true,
	}
	
	if staticExtensions[ext] {
		log.Printf("[REQ-%d] shouldFallbackToSPA: NO - Static asset extension", requestID)
		return false
	}
	
	// Check if the client accepts HTML (navigation request)
	// This is the primary indicator of a browser navigation request
	if strings.Contains(accept, "text/html") {
		log.Printf("[REQ-%d] shouldFallbackToSPA: YES - Accept contains text/html", requestID)
		return true
	}
	if accept == "*/*" || accept == "" {
		log.Printf("[REQ-%d] shouldFallbackToSPA: YES - Accept is wildcard or empty", requestID)
		return true
	}
	
	log.Printf("[REQ-%d] shouldFallbackToSPA: NO - No matching criteria", requestID)
	return false
}

// getFileExtension extracts the file extension from a path
func getFileExtension(path string) string {
	// Remove query string if present
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}
	
	// Find the last dot
	if idx := strings.LastIndex(path, "."); idx != -1 {
		return path[idx:]
	}
	
	return ""
}

// createProxyWithStaticFallback creates a handler that tries proxy first, then falls back to static files for 404s
func createProxyWithStaticFallback(targetURL string, staticDir string, fallbackPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get request ID from context
		requestID := uint64(0)
		if id, ok := r.Context().Value(RequestIDKey{}).(uint64); ok {
			requestID = id
		}
		
		log.Printf("[REQ-%d] ProxyWithStaticFallback: Starting for path %s", requestID, r.URL.Path)
		log.Printf("[REQ-%d] ProxyWithStaticFallback: Accept header: %s", requestID, r.Header.Get("Accept"))
		
		// Create a buffering response writer to capture the response
		brw := &bufferingResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			requestID:      requestID,
		}
		
		// Try the proxy first
		log.Printf("[REQ-%d] ProxyWithStaticFallback: Calling proxy for %s", requestID, targetURL)
		proxy := createReverseProxyWithFallback(targetURL, fallbackPath)
		proxy.ServeHTTP(brw, r)
		
		log.Printf("[REQ-%d] ProxyWithStaticFallback: Proxy returned status %d", requestID, brw.statusCode)
		
		// Check if we should serve the fallback
		if brw.statusCode == http.StatusNotFound && fallbackPath != "" {
			shouldFallback := shouldFallbackToSPA(r)
			log.Printf("[REQ-%d] ProxyWithStaticFallback: 404 detected, shouldFallback=%v", requestID, shouldFallback)
			
			if shouldFallback {
				log.Printf("[REQ-%d] ProxyWithStaticFallback: Serving SPA fallback from %s", requestID, staticDir+fallbackPath)
				// Don't write the buffered 404 response, serve the fallback instead
				http.ServeFile(w, r, staticDir+fallbackPath)
				return
			}
		}
		
		// Write the buffered response
		log.Printf("[REQ-%d] ProxyWithStaticFallback: Writing original response with status %d", requestID, brw.statusCode)
		w.WriteHeader(brw.statusCode)
		if brw.body.Len() > 0 {
			w.Write(brw.body.Bytes())
		}
	})
}

// createProxyWithProxyFallback creates a handler that fetches fallback from the proxy itself
func createProxyWithProxyFallback(targetURL string, fallbackPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get request ID from context
		requestID := uint64(0)
		if id, ok := r.Context().Value(RequestIDKey{}).(uint64); ok {
			requestID = id
		}
		
		log.Printf("[REQ-%d] ProxyWithProxyFallback: Starting for path %s", requestID, r.URL.Path)
		log.Printf("[REQ-%d] ProxyWithProxyFallback: Accept header: %s", requestID, r.Header.Get("Accept"))
		
		// Check if this is a streaming request (SSE)
		isStreaming := r.Header.Get("Accept") == "text/event-stream" ||
			strings.Contains(r.Header.Get("Accept"), "text/event-stream") ||
			strings.Contains(r.URL.Path, "/events") ||
			strings.Contains(r.URL.Path, "/stream") ||
			strings.Contains(r.URL.Path, "/sse")
		
		if isStreaming {
			// For streaming requests, bypass buffering entirely
			log.Printf("[REQ-%d] ProxyWithProxyFallback: Detected streaming request, bypassing buffering", requestID)
			proxy := createReverseProxy(targetURL)
			proxy.ServeHTTP(w, r)
			return
		}
		
		// For non-streaming requests, use buffering to check for 404
		// Create a buffering response writer to capture the response
		brw := &bufferingResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			requestID:      requestID,
		}
		
		// Try the proxy first
		log.Printf("[REQ-%d] ProxyWithProxyFallback: Calling proxy for %s", requestID, targetURL)
		proxy := createReverseProxyWithFallback(targetURL, fallbackPath)
		proxy.ServeHTTP(brw, r)
		
		log.Printf("[REQ-%d] ProxyWithProxyFallback: Proxy returned status %d", requestID, brw.statusCode)
		
		// Check if we should serve the fallback
		if brw.statusCode == http.StatusNotFound && fallbackPath != "" {
			shouldFallback := shouldFallbackToSPA(r)
			log.Printf("[REQ-%d] ProxyWithProxyFallback: 404 detected, shouldFallback=%v", requestID, shouldFallback)
			
			if shouldFallback {
				// Try to get fallback content from cache or proxy
				cacheKey := targetURL + fallbackPath
				fallbackContent := getFallbackContent(cacheKey, targetURL, fallbackPath, requestID)
				
				if fallbackContent != nil {
					log.Printf("[REQ-%d] ProxyWithProxyFallback: Serving SPA fallback (size: %d bytes)", requestID, len(fallbackContent))
					// Clear any headers from the buffered 404 response
					// This is important for HTTP/2 compliance
					for k := range w.Header() {
						delete(w.Header(), k)
					}
					// Set fresh headers for the fallback content
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
					w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fallbackContent)))
					w.WriteHeader(http.StatusOK)
					w.Write(fallbackContent)
					return
				} else {
					log.Printf("[REQ-%d] ProxyWithProxyFallback: Failed to get fallback content", requestID)
				}
			}
		}
		
		// Write the buffered response
		log.Printf("[REQ-%d] ProxyWithProxyFallback: Writing original response with status %d", requestID, brw.statusCode)
		// Copy headers from buffered response (if any were set)
		for k, v := range brw.Header() {
			w.Header()[k] = v
		}
		// Set Content-Length for non-streaming responses
		if brw.body.Len() > 0 {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", brw.body.Len()))
		}
		w.WriteHeader(brw.statusCode)
		if brw.body.Len() > 0 {
			w.Write(brw.body.Bytes())
		}
	})
}

// getFallbackContent retrieves fallback content from cache or fetches from proxy
func getFallbackContent(cacheKey string, targetURL string, fallbackPath string, requestID uint64) []byte {
	// Check cache first
	fallbackMutex.RLock()
	content, exists := fallbackCache[cacheKey]
	fallbackMutex.RUnlock()
	
	if exists {
		log.Printf("[REQ-%d] Using cached fallback content for %s", requestID, fallbackPath)
		return content
	}
	
	// Fetch from proxy
	log.Printf("[REQ-%d] Fetching fallback content from proxy: %s%s", requestID, targetURL, fallbackPath)
	
	// Parse the target URL
	target, err := url.Parse(targetURL)
	if err != nil {
		log.Printf("[REQ-%d] Error parsing proxy URL: %v", requestID, err)
		return nil
	}
	
	// Create the full URL for the fallback
	fallbackURL := *target
	fallbackURL.Path = fallbackPath
	
	// Create a new request for the fallback
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	resp, err := client.Get(fallbackURL.String())
	if err != nil {
		log.Printf("[REQ-%d] Error fetching fallback from proxy: %v", requestID, err)
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		log.Printf("[REQ-%d] Proxy returned non-200 status for fallback: %d", requestID, resp.StatusCode)
		return nil
	}
	
	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[REQ-%d] Error reading fallback response: %v", requestID, err)
		return nil
	}
	
	// Cache the content
	fallbackMutex.Lock()
	fallbackCache[cacheKey] = body
	fallbackMutex.Unlock()
	
	log.Printf("[REQ-%d] Cached fallback content for %s (size: %d bytes)", requestID, fallbackPath, len(body))
	return body
}

// bufferingResponseWriter buffers the entire response to allow for fallback decisions
type bufferingResponseWriter struct {
	http.ResponseWriter
	statusCode    int
	headerWritten bool
	body          bytes.Buffer
	requestID     uint64
}

func (w *bufferingResponseWriter) WriteHeader(status int) {
	if !w.headerWritten {
		w.statusCode = status
		w.headerWritten = true
		log.Printf("[REQ-%d] BufferingResponseWriter: Captured status %d", w.requestID, status)
		// Don't write to the underlying ResponseWriter yet
	}
}

func (w *bufferingResponseWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}
	// Buffer the response body
	n, err := w.body.Write(b)
	log.Printf("[REQ-%d] BufferingResponseWriter: Buffered %d bytes (total: %d)", w.requestID, n, w.body.Len())
	return n, err
}

func manageCertificates() {
	var wg sync.WaitGroup
	for domain := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			for {
				log.Printf("Checking certificate for domain: %s", domain)
				cert, err := certManager.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
				if err != nil {
					log.Printf("Error obtaining certificate for domain %s: %v", domain, err)
					time.Sleep(5 * time.Minute)
					continue
				}
				log.Printf("Certificate obtained successfully for domain: %s (expires: %s)", domain, cert.Leaf.NotAfter)
				// Check expiration and renew if necessary
				if cert.Leaf.NotAfter.Before(time.Now().Add(30 * 24 * time.Hour)) {
					log.Printf("Certificate for %s is nearing expiration. Attempting renewal.", domain)
					_, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
					newCert, err := certManager.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
					cancel()
					if err != nil {
						log.Printf("Error renewing certificate for %s: %v", domain, err)
					} else {
						log.Printf("Certificate renewed successfully for %s (new expiration: %s)", domain, newCert.Leaf.NotAfter)
					}
				}
				// Sleep for a day before checking again
				time.Sleep(24 * time.Hour)
			}
		}(domain)
	}
	wg.Wait()
}

// requestIDMiddleware adds a unique request ID to each request
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate unique request ID
		requestID := atomic.AddUint64(&requestCounter, 1)

		// Add to context
		ctx := context.WithValue(r.Context(), RequestIDKey{}, requestID)
		r = r.WithContext(ctx)

		// Add to response header for debugging
		w.Header().Set("X-Request-ID", fmt.Sprintf("%d", requestID))

		// Log request start with all headers for SSE debugging
		if strings.Contains(r.Header.Get("Accept"), "text/event-stream") ||
			strings.Contains(r.URL.Path, "/stream") ||
			strings.Contains(r.URL.Path, "/events") ||
			strings.Contains(r.URL.Path, "/sse") {
			log.Printf("[REQ-%d] SSE Request detected - Method: %s, Path: %s, Accept: %s, User-Agent: %s",
				requestID, r.Method, r.URL.Path, r.Header.Get("Accept"), r.Header.Get("User-Agent"))
		}

		next.ServeHTTP(w, r)
	})
}

// trackedResponseWriter wraps ResponseWriter to track response details
type trackedResponseWriter struct {
	http.ResponseWriter
	requestID  uint64
	statusCode int
	written    int64
	startTime  time.Time
}

func (w *trackedResponseWriter) WriteHeader(status int) {
	w.statusCode = status
	log.Printf("[REQ-%d] Writing response header - Status: %d, Time elapsed: %v",
		w.requestID, status, time.Since(w.startTime))
	w.ResponseWriter.WriteHeader(status)
}

func (w *trackedResponseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += int64(n)

	// Log write errors
	if err != nil {
		log.Printf("[REQ-%d] Write error after %d bytes, elapsed: %v - Error: %v",
			w.requestID, w.written, time.Since(w.startTime), err)
	}

	return n, err
}

func (w *trackedResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Get request ID from context
		requestID := uint64(0)
		if id, ok := r.Context().Value(RequestIDKey{}).(uint64); ok {
			requestID = id
		}

		// Log request details
		log.Printf("[REQ-%d] START - %s %s from %s, Host: %s, Content-Type: %s",
			requestID, r.Method, r.URL.Path, r.RemoteAddr, r.Host, r.Header.Get("Content-Type"))

		// Wrap response writer to track details
		tracked := &trackedResponseWriter{
			ResponseWriter: w,
			requestID:      requestID,
			startTime:      start,
		}

		// Set up a timer to log if request is still running after 30 seconds
		timer := time.AfterFunc(30*time.Second, func() {
			log.Printf("[REQ-%d] WARNING: Request still running after 30 seconds - %s %s",
				requestID, r.Method, r.URL.Path)
		})

		// Set up another timer for 36 seconds
		timer36 := time.AfterFunc(36*time.Second, func() {
			log.Printf("[REQ-%d] WARNING: Request still running after 36 seconds - %s %s",
				requestID, r.Method, r.URL.Path)
		})

		next.ServeHTTP(tracked, r)

		// Cancel timers
		timer.Stop()
		timer36.Stop()

		duration := time.Since(start)
		log.Printf("[REQ-%d] END - %s %s - Status: %d, Bytes: %d, Duration: %v",
			requestID, r.Method, r.URL.Path, tracked.statusCode, tracked.written, duration)

		// Log warning for requests that took close to timeout values
		if duration > 29*time.Second && duration < 31*time.Second {
			log.Printf("[REQ-%d] WARNING: Request duration near 30s timeout: %v", requestID, duration)
		} else if duration > 35*time.Second && duration < 37*time.Second {
			log.Printf("[REQ-%d] WARNING: Request duration near 36s mark: %v", requestID, duration)
		}
	})
}

func wrapHandlerWithLogging(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Received request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		handler.ServeHTTP(w, r)
		log.Printf(
			"Completed request: %s %s from %s in %s",
			r.Method,
			r.URL.Path,
			r.RemoteAddr,
			time.Since(start),
		)
	})
}

func loggedGetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	log.Printf("GetCertificate called for ServerName: %s", hello.ServerName)
	cert, err := certManager.GetCertificate(hello)
	if err != nil {
		log.Printf("Error getting certificate for %s: %v", hello.ServerName, err)
	} else {
		if cert != nil && cert.Leaf != nil {
			log.Printf("Certificate obtained for %s (expires: %s)", hello.ServerName, cert.Leaf.NotAfter)
		} else {
			log.Printf("Certificate obtained for %s (expires: %v)", hello.ServerName, cert)
		}
	}
	return cert, err
}

func logConnState(conn net.Conn, state http.ConnState) {
	timestamp := time.Now().Format("15:04:05.000")
	log.Printf("[CONN] %s - %s -> %s", timestamp, conn.RemoteAddr(), state)

	// Log additional details for connection close events
	if state == http.StateClosed || state == http.StateHijacked {
		log.Printf("[CONN] %s - Connection closed/hijacked: %s", timestamp, conn.RemoteAddr())
	}
}

func basicAuthMiddleware(next http.Handler, config DomainConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth check if no auth is configured
		if config.BasicAuth.Username == "" && config.BasicAuth.Password == "" {
			next.ServeHTTP(w, r)
			return
		}

		username, password, ok := r.BasicAuth()
		if !ok || username != config.BasicAuth.Username || password != config.BasicAuth.Password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// shouldCompress checks if the content type should be compressed
func shouldCompress(contentType string) bool {
	// Extract the base content type without parameters
	if semicolon := strings.Index(contentType, ";"); semicolon != -1 {
		contentType = contentType[:semicolon]
	}
	contentType = strings.TrimSpace(strings.ToLower(contentType))

	// List of content types that are already compressed or shouldn't be compressed
	skipCompression := map[string]bool{
		"image/png":                    true,
		"image/jpeg":                   true,
		"image/gif":                    true,
		"image/webp":                   true,
		"image/avif":                   true,
		"video/":                       true,
		"audio/":                       true,
		"application/zip":              true,
		"application/gzip":             true,
		"application/x-gzip":           true,
		"application/x-compress":       true,
		"application/x-compressed":     true,
		"application/x-zip-compressed": true,
		"application/octet-stream":     true,
	}

	// Check if content type starts with any of the skip prefixes
	for prefix := range skipCompression {
		if strings.HasPrefix(contentType, prefix) {
			return false
		}
	}

	// Only compress known compressible types
	return strings.HasPrefix(contentType, "text/") ||
		contentType == "application/json" ||
		contentType == "application/javascript" ||
		contentType == "application/xml" ||
		contentType == "application/x-www-form-urlencoded" ||
		strings.HasSuffix(contentType, "+json") ||
		strings.HasSuffix(contentType, "+xml")
}

func compressionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get request ID from context
		requestID := uint64(0)
		if id, ok := r.Context().Value(RequestIDKey{}).(uint64); ok {
			requestID = id
		}

		// Early detection of special protocols
		isWebSocket := websocket.IsWebSocketUpgrade(r)
		isSSE := r.Header.Get("Accept") == "text/event-stream" ||
			strings.Contains(r.Header.Get("Accept"), "text/event-stream")
		isStreaming := strings.Contains(r.URL.Path, "/stream") ||
			strings.Contains(r.URL.Path, "/events") ||
			strings.Contains(r.URL.Path, "/sse") ||
			isSSE

		// Skip compression for special cases
		if *disableCompression || isWebSocket || isSSE || isStreaming {
			if isSSE || isStreaming {
				log.Printf("[REQ-%d] Skipping compression for SSE/streaming request", requestID)
			}
			next.ServeHTTP(w, r)
			return
		}

		// Check if client accepts gzip
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		// Don't set Vary header here - let the compressResponseWriter decide
		// Check if this is a HEAD request
		isHEAD := r.Method == http.MethodHead

		var crw *compressResponseWriter
		if !isHEAD {
			gz := gzip.NewWriter(w)
			crw = &compressResponseWriter{
				ResponseWriter: w,
				gzWriter:       gz,
				wroteBody:      false,
				statusCode:     http.StatusOK,
				requestID:      requestID,
			}
		} else {
			// For HEAD requests, don't create a gzip writer at all
			crw = &compressResponseWriter{
				ResponseWriter: w,
				gzWriter:       nil,
				doCompress:     false,
				wroteBody:      false,
				statusCode:     http.StatusOK,
				requestID:      requestID,
			}
		}

		// Serve the request
		next.ServeHTTP(crw, r)

		// After handler completes, ensure all data is flushed before response ends
		// This is critical for small responses that might be buffered
		if crw.doCompress && crw.gzWriter != nil && crw.wroteBody {
			// Flush any remaining compressed data
			if err := crw.gzWriter.Flush(); err != nil {
				log.Printf("Error flushing gzip writer: %v", err)
			}
			// Close the gzip writer to write the trailer
			if err := crw.gzWriter.Close(); err != nil {
				// Only log if it's not the expected "no body allowed" error
				if !strings.Contains(err.Error(), "does not allow body") {
					log.Printf("Error closing gzip writer: %v", err)
				}
			}
		}

		// Ensure the response is fully sent to the client
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	})
}
