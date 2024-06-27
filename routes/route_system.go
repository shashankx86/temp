// routes/routes_system.go

package routes

import (
	"encoding/json"
	"net/http"
	"os/exec"

	"github.com/gorilla/mux"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/middleware/stdlib"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

var (
	systemLimiterStore = memory.NewStore()
	systemRate         = limiter.Rate{
		Period: 1 * time.Minute,
		Limit:  70,
	}
	systemLimiter       = limiter.New(systemLimiterStore, systemRate)
	systemLimiterMiddleware = stdlib.NewMiddleware(systemLimiter)
)

type Unit struct {
	UNIT        string `json:"UNIT"`
	LOAD        string `json:"LOAD"`
	ACTIVE      string `json:"ACTIVE"`
	SUB         string `json:"SUB"`
	DESCRIPTION string `json:"DESCRIPTION"`
}

func executeCommand(command string) (string, error) {
	out, err := exec.Command("sh", "-c", command).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func parseUnits(data string) []Unit {
	unitRegex := `^\s*(\S+\.service|\S+\.socket)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$`
	matches := regexp.MustCompile(unitRegex).FindAllStringSubmatch(data, -1)
	units := []Unit{}
	for _, match := range matches {
		units = append(units, Unit{
			UNIT:        match[1],
			LOAD:        match[2],
			ACTIVE:      match[3],
			SUB:         match[4],
			DESCRIPTION: match[5],
		})
	}
	return units
}

func ListServices(w http.ResponseWriter, r *http.Request) {
	serviceStdout, err := executeCommand("systemctl --user list-units --type=service --state=running")
	if err != nil {
		http.Error(w, "Error fetching services", http.StatusInternalServerError)
		return
	}
	services := parseUnits(serviceStdout)

	socketStdout, err := executeCommand("systemctl --user list-units --type=socket")
	if err != nil {
		http.Error(w, "Error fetching sockets", http.StatusInternalServerError)
		return
	}
	sockets := parseUnits(socketStdout)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"services": services,
		"sockets":  sockets,
	})
}

func RegisterSystemRoutes(r *mux.Router) {
	systemRouter := r.PathPrefix("/system").Subrouter()

	systemRouter.Use(systemLimiterMiddleware.Handler)

	systemRouter.HandleFunc("/services", ListServices).Methods("GET")
}
