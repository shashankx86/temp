package main

import (
    "context"
    "crypto/rsa"
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
    VERSION     string
    LOG         bool
    V_LOG       bool
    privateKey  *rsa.PrivateKey
    publicKey   *rsa.PublicKey
    refreshSecret string
    username    string
    password    string
)

func init() {
    // Load environment variables from .env file
    if err := godotenv.Load(); err != nil {
        log.Printf("Error loading .env file: %v", err)
    }

    // Load refresh secret and user credentials from environment variables
    refreshSecret = os.Getenv("REFRESH_SECRET")
    username = os.Getenv("USERNAME")
    password = os.Getenv("PASSWORD")

    // Load version from environment variables
    VERSION = "0.0.3"

    // Load logging flags
    LOG = true
    V_LOG = true

    // Load the private key
    privateKeyData, err := os.ReadFile("keys/private_key.pem")
    if err != nil {
        log.Fatalf("Error reading private key: %v", err)
    }
    privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
    if err != nil {
        log.Fatalf("Error parsing private key: %v", err)
    }

    // Load the public key
    publicKeyData, err := os.ReadFile("keys//public_key.pem")
    if err != nil {
        log.Fatalf("Error reading public key: %v", err)
    }
    publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
    if err != nil {
        log.Fatalf("Error parsing public key: %v", err)
    }

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
    corsOptions := cors.Options{
        // Get the current user's username on the host machine
        // currentUser, err := user.Current()
        // if err != nil {
        //     log.Fatalf("Error getting current user: %v", err)
        // }
        // serverUsername := currentUser.Username

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

    // General rate limiter configuration for all routes except login and refresh
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

    // Rate limiter configuration for refresh route
    refreshRate := limiter.Rate{
        Period: 1 * time.Minute,
        Limit:  20,
    }
    refreshLimiterStore := memory.NewStore()
    refreshLimiter := limiter.New(refreshLimiterStore, refreshRate)
    refreshLimiterMiddleware := stdlib.NewMiddleware(refreshLimiter)

    // Login endpoint with specific rate limiter
    r.Handle("/login", loginLimiterMiddleware.Handler(http.HandlerFunc(loginHandler))).Methods("POST", "OPTIONS")

    // Refresh endpoint with specific rate limiter
    r.Handle("/refresh", refreshLimiterMiddleware.Handler(http.HandlerFunc(refreshHandler))).Methods("POST", "OPTIONS")

    // Protected routes
    r.Handle("/version", isAuthenticated(http.HandlerFunc(versionHandler))).Methods("GET", "OPTIONS")

    // Handle preflight requests
    r.HandleFunc("/login", optionsHandler).Methods("OPTIONS")
    r.HandleFunc("/refresh", optionsHandler).Methods("OPTIONS")
    r.HandleFunc("/version", optionsHandler).Methods("OPTIONS")

    // Apply general rate limiting to all routes except login and refresh
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

    // Create access and refresh tokens
    accessToken, err := createToken(creds.Username, 15*time.Minute)
    if err != nil {
        http.Error(w, "Error generating access token", http.StatusInternalServerError)
        return
    }

    refreshToken, err := createToken(creds.Username, 7*24*time.Hour)
    if err != nil {
        http.Error(w, "Error generating refresh token", http.StatusInternalServerError)
        return
    }

    if V_LOG {
        log.Printf("User %s logged in at %s from IP %s", creds.Username, time.Now().Format(time.RFC3339), r.RemoteAddr)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message":      "Login successful",
        "access_token": accessToken,
        "refresh_token": refreshToken,
    })
}

// Handles refresh token requests
func refreshHandler(w http.ResponseWriter, r *http.Request) {
    var requestData struct {
        RefreshToken string `json:"refresh_token"`
    }

    err := json.NewDecoder(r.Body).Decode(&requestData)
    if err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    token, err := jwt.Parse(requestData.RefreshToken, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
            log.Printf("Unexpected signing method: %v", token.Header["alg"])
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return publicKey, nil
    })

    if err != nil {
        log.Printf("Error parsing refresh token: %v", err)
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    if !token.Valid {
        log.Printf("Invalid refresh token")
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        log.Printf("Invalid refresh token claims")
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    username := claims["username"].(string)

    // Create new access token
    newAccessToken, err := createToken(username, 15*time.Minute)
    if err != nil {
        http.Error(w, "Error generating new access token", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "access_token": newAccessToken,
    })
}

// Middleware to check if the user is authenticated
func isAuthenticated(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            log.Printf("Missing Authorization header")
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Extract the token from the "Bearer " prefix
        if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
            log.Printf("Malformed Authorization header")
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        tokenString := authHeader[7:]
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
                log.Printf("Unexpected signing method: %v", token.Header["alg"])
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
            }
            return publicKey, nil
        })

        if err != nil {
            log.Printf("Error parsing token: %v", err)
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        if !token.Valid {
            log.Printf("Invalid token")
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            log.Printf("Invalid token claims")
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        log.Printf("Token claims: %v", claims)

        // Add claims to the request context
        ctx := context.WithValue(r.Context(), "user", claims["username"])
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// Handles requests to retrieve the version
func versionHandler(w http.ResponseWriter, r *http.Request) {
    user, ok := r.Context().Value("user").(string)
    if !ok {
        log.Printf("User context not found")
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    log.Printf("User %s accessed version endpoint", user)

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "version": VERSION,
        "user":    user,
    })
}

// Helper function to create a JWT token
func createToken(username string, expiry time.Duration) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
        "username": username,
        "exp":      time.Now().Add(expiry).Unix(),
    })

    tokenString, err := token.SignedString(privateKey)
    if err != nil {
        return "", err
    }

    return tokenString, nil
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
