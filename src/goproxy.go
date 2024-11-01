package main

// -build-me-for: linux
import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type DomainConfig struct {
	StaticDir string
	ProxyURLs map[string]string
}

var (
	domains     map[string]DomainConfig
	certManager *autocert.Manager
)

func main() {
	// Parse command-line flags
	configFile := flag.String("config", "config.txt", "Path to the configuration file")
	flag.Parse()

	// Load configuration
	err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	// Initialize autocert manager
	certManager = createCertManager(getDomainNames())

	// Create the main router
	mainRouter := mux.NewRouter()

	// Add logging middleware
	mainRouter.Use(loggingMiddleware)

	// Set up routes for each domain
	for domain, config := range domains {
		router := mainRouter.Host(domain).Subrouter()

		// Set up static file serving
		fs := http.FileServer(http.Dir(config.StaticDir))
		router.PathPrefix("/").Handler(http.StripPrefix("/", fs))

		// Set up proxy routes
		for path, targetURL := range config.ProxyURLs {
			proxy := createReverseProxy(targetURL)
			router.PathPrefix(path).Handler(proxy)
		}
	}

	// Set up the TLS configuration
	tlsConfig := &tls.Config{
		GetCertificate: loggedGetCertificate,
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
	}

	// Set up the HTTPS server
	server := &http.Server{
		Addr:      ":https",
		Handler:   mainRouter,
		TLSConfig: tlsConfig,
		ErrorLog:  log.New(os.Stderr, "HTTPS Server Error: ", log.Ldate|log.Ltime|log.Lshortfile),
		ConnState: logConnState,
	}

	// Start certificate management
	go manageCertificates()

	// Start HTTP-01 challenge server
	go func() {
		log.Println("Starting HTTP server for ACME challenges on :80")
		httpServer := &http.Server{
			Addr:      ":http",
			Handler:   wrapHandlerWithLogging(certManager.HTTPHandler(nil)),
			ConnState: logConnState,
		}
		if err := httpServer.ListenAndServe(); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Start the HTTPS server
	log.Println("Starting HTTPS server on :443")
	log.Fatal(server.ListenAndServeTLS("", ""))
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

func createCertManager(domains []string) *autocert.Manager {
	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
		Cache:      autocert.DirCache("certs"),
		Email:      "your-email@example.com", // Replace with your email
	}
}

func createReverseProxy(targetURL string) *httputil.ReverseProxy {
	url, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("Error parsing proxy URL: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(url)

	// Modify the Director function to handle WebSocket requests
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Check if this is a WebSocket request
		if websocket.IsWebSocketUpgrade(req) {
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
		}
	}

	// Add error handling
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
	}

	return proxy
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

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Received request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
		log.Printf(
			"Completed request: %s %s from %s in %s",
			r.Method,
			r.URL.Path,
			r.RemoteAddr,
			time.Since(start),
		)
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
	log.Printf("Connection state changed: %s -> %s", conn.RemoteAddr(), state)
}
