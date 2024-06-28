package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/user"
	"time"

	"github.com/go-chi/cors"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/msteinert/pam"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/middleware/stdlib"
	"github.com/ulule/limiter/v3/drivers/store/memory"

	"napi/components"
	"napi/routes"
)

var (
	store   *sessions.CookieStore
	VERSION string
	LOG     bool
	V_LOG   bool
)

func init() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Error loading .env file: %v", err)
	}

	// Initialize session store with key from environment variable
	key := []byte(os.Getenv("SESSION_KEY"))
	store = sessions.NewCookieStore(key)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   0,    // Session cookie expires when the browser closes
		HttpOnly: true, // Prevent JavaScript access to the cookie
		Secure:   true, // Ensure the cookie is only sent over HTTPS
		SameSite: http.SameSiteStrictMode, // Prevent CSRF
	}

	// Load version from environment variables
	VERSION = os.Getenv("VERSION")

	// Load logging flags
	LOG = true
	V_LOG = true

	// Set up logging to file
	setupLogging()
}

// setupLogging initializes logging to a file, appending to it if it exists
func setupLogging() {
	logFile, err := os.OpenFile("serve.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(logFile)
	log.Printf("Server started at: %s", time.Now().Format(time.RFC3339))
}

func main() {
	// Get the current user's username on the host machine
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("Error getting current user: %v", err)
	}
	serverUsername := currentUser.Username

	corsOptions := cors.Options{
		AllowedOrigins:   []string{"https://ncwi." + serverUsername + ".hackclub.app", "http://localhost"},
		AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}

	r := mux.NewRouter()

	// Apply CORS middleware
	r.Use(cors.Handler(corsOptions))

	// Apply security headers middleware
	r.Use(securityHeadersMiddleware)

	// General rate limiter configuration for all routes except login and system
	generalRate := limiter.Rate{
		Period: 1 * time.Minute,
		Limit:  60,
	}
	generalLimiterStore := memory.NewStore()
	generalLimiter := limiter.New(generalLimiterStore, generalRate)
	generalLimiterMiddleware := stdlib.NewMiddleware(generalLimiter)

	// Rate limiter configuration for login route
	loginRate := limiter.Rate{
		Period: 1 * time.Minute,
		Limit:  40,
	}
	loginLimiterStore := memory.NewStore()
	loginLimiter := limiter.New(loginLimiterStore, loginRate)
	loginLimiterMiddleware := stdlib.NewMiddleware(loginLimiter)

	// Login endpoint with specific rate limiter
	r.Handle("/login", loginLimiterMiddleware.Handler(http.HandlerFunc(loginHandler))).Methods("POST", "OPTIONS")

	// Protected routes
	r.Handle("/version", isAuthenticated(http.HandlerFunc(versionHandler))).Methods("GET", "OPTIONS")

	// Handle preflight requests
	r.HandleFunc("/login", optionsHandler).Methods("OPTIONS")
	r.HandleFunc("/version", optionsHandler).Methods("OPTIONS")

	// Apply general rate limiting to all routes except login
	r.Use(generalLimiterMiddleware.Handler)

	// Register system and docker routes with specific rate limiter
	systemRouter := r.PathPrefix("/io").Subrouter()
	systemRate := limiter.Rate{
		Period: 1 * time.Minute,
		Limit:  70,
	}
	systemLimiterStore := memory.NewStore()
	systemLimiter := limiter.New(systemLimiterStore, systemRate)
	systemRouter.Use(stdlib.NewMiddleware(systemLimiter).Handler)
	systemRouter.Use(isAuthenticated)
	routes.RegisterSystemRoutes(systemRouter)
	routes.DockerHandler(systemRouter)

	port := os.Getenv("PORT")
	if port == "" {
		port = "5499"
	}

	websocketPort := os.Getenv("WEBSOCKET_PORT")
	if websocketPort == "" {
		websocketPort = "5498"
	}

	// Start HTTP API server
	go func() {
		log.Printf("API server is running on port %s", port)
		log.Fatal(http.ListenAndServe(":"+port, r))
	}()

	// Start WebSocket server
	go func() {
		go components.StartWebSocketServer()
	}()

	// Block the main goroutine
	select {}
}

// Handles the login requests and validates the user credentials using PAM
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// Decode the JSON request payload
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate the provided credentials using PAM
	t, err := pam.StartFunc("", creds.Username, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return creds.Password, nil
		case pam.PromptEchoOn:
			return creds.Username, nil
		case pam.ErrorMsg:
			return "", nil
		case pam.TextInfo:
			return "", nil
		}
		return "", fmt.Errorf("Unrecognized PAM message style: %v", s)
	})

	if err != nil {
		http.Error(w, "PAM authentication failed", http.StatusUnauthorized)
		return
	}

	err = t.Authenticate(0)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Invalidate previous session if exists
	session, _ := store.Get(r, "session")
	session.Values = make(map[interface{}]interface{})
	session.Save(r, w)

	// Create a new session
	session, _ = store.Get(r, "session")
	session.Values["user"] = creds.Username
	session.Values["lastActivity"] = time.Now()
	session.Values["ip"] = r.RemoteAddr
	session.Values["userAgent"] = r.UserAgent()
	session.Save(r, w)

	if V_LOG {
		log.Printf("User %s logged in at %s from IP %s", creds.Username, time.Now().Format(time.RFC3339), r.RemoteAddr)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":   "Login successful",
		"sessionId": session.ID,
	})
}

// Middleware to check if the user is authenticated
func isAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")

		userExists := session.Values["user"] != nil
		lastActivity, lastActivityExists := session.Values["lastActivity"].(time.Time)
		savedIP, ipExists := session.Values["ip"].(string)
		savedUserAgent, userAgentExists := session.Values["userAgent"].(string)

		if userExists && lastActivityExists && ipExists && userAgentExists &&
			time.Since(lastActivity) <= 30*time.Minute &&
			savedIP == r.RemoteAddr &&
			savedUserAgent == r.UserAgent() {
			// Update last activity timestamp
			session.Values["lastActivity"] = time.Now()
			session.Save(r, w)
			next.ServeHTTP(w, r)
		} else {
			session.Options.MaxAge = -1 // Invalidate the session
			session.Save(r, w)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	})
}

// Handles requests to retrieve the version
func versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"version": VERSION,
	})
}

// Handles OPTIONS requests for CORS preflight
func optionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.WriteHeader(http.StatusOK)
}

// Middleware to add security-related headers to responses
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}
