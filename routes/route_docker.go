// routes/router_docker.go

package routes

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"

	"github.com/gorilla/mux"
)

// Helper function to execute shell commands
func executeCommand(command string, args ...string) (string, error) {
	out, err := exec.Command(command, args...).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Endpoint to list running Docker containers
func listRunningContainers(w http.ResponseWriter, r *http.Request) {
	output, err := executeCommand("docker", "ps")
	if err != nil {
		http.Error(w, "Error fetching running containers: "+err.Error(), http.StatusInternalServerError)
		return
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 {
		http.Error(w, "No running containers found", http.StatusNoContent)
		return
	}

	headers := strings.Fields(lines[0])
	containers := make([]map[string]string, 0, len(lines)-1)

	for _, line := range lines[1:] {
		columns := strings.Fields(line)
		container := make(map[string]string)
		for i, header := range headers {
			container[strings.ReplaceAll(header, " ", "_")] = columns[i]
		}
		containers = append(containers, container)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{"containers": containers})
}

// DockerHandler defines the handler for Docker-related routes
func DockerHandler(router *mux.Router) {
	dockerRouter := router.PathPrefix("/docker").Subrouter()

	dockerRouter.HandleFunc("/running", listRunningContainers).Methods("GET", "OPTIONS")
}
