package routes

import (
    "encoding/json"
    "log"
    "net/http"
    "os/exec"
    "strings"

    "github.com/gorilla/mux"
)

type SystemUsage struct {
    Disk   Usage `json:"disk"`
    Memory Usage `json:"memory"`
}

type Usage struct {
    Total string `json:"total"`
    Used  string `json:"used"`
}

// Helper function to execute shell commands
func executeCommandN(command string, args ...string) (string, error) {
    out, err := exec.Command(command, args...).Output()
    if err != nil {
        return "", err
    }
    return string(out), nil
}

func NestResourcesHandler(w http.ResponseWriter, r *http.Request) {
    log.Println("Executing command: nest resources")
    output, err := executeCommandN("sh", "-c", "nest resources")
    if err != nil {
        log.Printf("Failed to execute command: %v", err)
        http.Error(w, "Failed to execute command: "+err.Error(), http.StatusInternalServerError)
        return
    }

    log.Printf("Command output: %s", output)
    lines := strings.Split(strings.TrimSpace(output), "\n")
    if len(lines) < 2 {
        log.Println("Unexpected command output")
        http.Error(w, "Unexpected command output", http.StatusInternalServerError)
        return
    }

    // Parse Disk usage line
    diskLineParts := strings.Split(lines[1], " ")
    if len(diskLineParts) < 7 {
        log.Println("Unexpected disk usage format")
        http.Error(w, "Unexpected disk usage format", http.StatusInternalServerError)
        return
    }

    // Parse Memory usage line
    memoryLineParts := strings.Split(lines[2], " ")
    if len(memoryLineParts) < 7 {
        log.Println("Unexpected memory usage format")
        http.Error(w, "Unexpected memory usage format", http.StatusInternalServerError)
        return
    }

    usage := SystemUsage{
        Disk: Usage{
            Total: diskLineParts[6],  // "15.0 GB"
            Used:  diskLineParts[2],  // "4.58 GB"
        },
        Memory: Usage{
            Total: memoryLineParts[6],  // "3.0 GB"
            Used:  memoryLineParts[2],  // "3.0 GB"
        },
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]interface{}{"usage": usage})
}

func NestHandler(router *mux.Router) {
    nestRouter := router.PathPrefix("/nest").Subrouter()
    nestRouter.HandleFunc("/resources", NestResourcesHandler).Methods("GET", "OPTIONS")
}
