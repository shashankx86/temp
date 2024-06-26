package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/cors"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/middleware/stdlib"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

var (
	key   = []byte("secret-key")
	store = sessions.NewCookieStore(key)
)

const (
	USERNAME = "test"
	PASSWORD = "test"
	VERSION  = "0.0.1"
)

func main() {
	serverUsername := os.Getenv("USER")
	corsOptions := cors.Options{
		AllowedOrigins:   []string{"https://ncwi." + serverUsername + ".hackclub.app"},
		AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}

	r := mux.NewRouter()

	// Apply CORS middleware
	r.Use(cors.Handler(corsOptions))

	// General rate limiter configuration for other routes
	generalRate, err := limiter.NewRateFromFormatted("10-M")
	if err != nil {
		log.Fatal(err)
	}
	generalLimiterStore := memory.NewStore()
	generalLimiter := limiter.New(generalLimiterStore, generalRate)
	generalLimiterMiddleware := stdlib.NewMiddleware(generalLimiter)

	// Rate limiter configuration for login route
	loginRate := limiter.Rate{
		Period: 10 * time.Minute,
		Limit:  25,
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

	port := os.Getenv("PORT")
	if port == "" {
		port = "5499"
	}
	log.Printf("Server is running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if creds.Username == USERNAME && creds.Password == PASSWORD {
		session, _ := store.Get(r, "session")
		session.Values["user"] = USERNAME
		session.Save(r, w)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":   "Login successful",
			"sessionId": session.ID,
		})
	} else {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
	}
}

func isAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		if session.Values["user"] != nil {
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	})
}

func versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"version": VERSION,
	})
}

func optionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.WriteHeader(http.StatusNoContent)
}
