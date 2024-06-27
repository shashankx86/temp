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

// Endpoint to list Docker images
func listDockerImages(w http.ResponseWriter, r *http.Request) {
	output, err := executeCommand("docker", "image", "ls")
	if err != nil {
		http.Error(w, "Error fetching Docker images: "+err.Error(), http.StatusInternalServerError)
		return
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	headers := strings.Fields(lines[0])
	images := make([]map[string]string, 0, len(lines)-1)

	for _, line := range lines[1:] {
		columns := strings.Fields(line)
		image := make(map[string]string)
		for i, header := range headers {
			image[strings.ReplaceAll(header, " ", "_")] = columns[i]
		}
		images = append(images, image)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{"images": images})
}

// Endpoint to start a Docker container
func startContainer(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target is required", http.StatusBadRequest)
		return
	}
	if err := exec.Command("docker", "start", target).Run(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Container started successfully"})
}

// Endpoint to stop a Docker container
func stopContainer(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target is required", http.StatusBadRequest)
		return
	}
	if err := exec.Command("docker", "stop", target).Run(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Container stopped successfully"})
}

// Endpoint to restart a Docker container
func restartContainer(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target is required", http.StatusBadRequest)
		return
	}
	if err := exec.Command("docker", "restart", target).Run(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Container restarted successfully"})
}

// Endpoint to remove a Docker image
func removeDockerImage(w http.ResponseWriter, r *http.Request) {
	targetID := r.URL.Query().Get("targetid")
	if targetID == "" {
		http.Error(w, "targetid is required", http.StatusBadRequest)
		return
	}

	forceFlag := ""
	if r.URL.Query().Get("toforce") == "true" {
		forceFlag = "--force"
	}

	args := []string{"image", "rm", targetID}
	if forceFlag != "" {
		args = append(args, forceFlag)
	}

	if _, err := executeCommand("docker", args...); err != nil {
		http.Error(w, "Error removing image: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Image removed successfully"})
}

// DockerHandler defines the handler for Docker-related routes
func DockerHandler(router *mux.Router) {
	dockerRouter := router.PathPrefix("/docker").Subrouter()

	dockerRouter.HandleFunc("/running", listRunningContainers).Methods("GET", "OPTIONS")
	dockerRouter.HandleFunc("/start", startContainer).Methods("POST", "OPTIONS")
	dockerRouter.HandleFunc("/stop", stopContainer).Methods("POST", "OPTIONS")
	dockerRouter.HandleFunc("/restart", restartContainer).Methods("POST", "OPTIONS")
	dockerRouter.HandleFunc("/image/ls", listDockerImages).Methods("GET", "OPTIONS")
	dockerRouter.HandleFunc("/image/rm", removeDockerImage).Methods("DELETE", "OPTIONS")
}
