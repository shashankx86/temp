package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    // "os/user"
    "time"

    "github.com/go-chi/cors"
    "github.com/gorilla/mux"
    "github.com/joho/godotenv"
    "github.com/ulule/limiter/v3"
    "github.com/ulule/limiter/v3/drivers/middleware/stdlib"
    "github.com/ulule/limiter/v3/drivers/store/memory"
    "github.com/dgrijalva/jwt-go"

    "napi/components"
    "napi/routes"
)

var (
    VERSION string
    LOG     bool
    V_LOG   bool
    jwtSecret string
    username  string
    password  string
)

func init() {
    // Load environment variables from .env file
    if err := godotenv.Load(); err != nil {
        log.Printf("Error loading .env file: %v", err)
    }

    // Load JWT secret and user credentials from environment variables
    jwtSecret = os.Getenv("JWT_SECRET")
    username = os.Getenv("USERNAME")
    password = os.Getenv("PASSWORD")

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
    // currentUser, err := user.Current()
    // if err != nil {
    //     log.Fatalf("Error getting current user: %v", err)
    // }
    // serverUsername := currentUser.Username

    corsOptions := cors.Options{
        AllowedOrigins:   []string{"*"},
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
        components.StartWebSocketServer()
    }()

    // Block the main goroutine
    select {}
}

// Handles the login requests and validates the user credentials
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

    // Validate the provided credentials
    if creds.Username != username || creds.Password != password {
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    // Create JWT token
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "username": creds.Username,
        "exp":      time.Now().Add(time.Hour * 72).Unix(),
    })

    tokenString, err := token.SignedString([]byte(jwtSecret))
    if err != nil {
        http.Error(w, "Error generating token", http.StatusInternalServerError)
        return
    }

    if V_LOG {
        log.Printf("User %s logged in at %s from IP %s", creds.Username, time.Now().Format(time.RFC3339), r.RemoteAddr)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Login successful",
        "token":   tokenString,
    })
}

// Middleware to check if the user is authenticated
func isAuthenticated(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tokenString := r.Header.Get("Authorization")
        if tokenString == "" {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
            }
            return []byte(jwtSecret), nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        next.ServeHTTP(w, r)
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
