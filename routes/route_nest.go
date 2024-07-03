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
    diskLineParts := strings.Fields(lines[0])
    if len(diskLineParts) < 8 {
        log.Println("Unexpected disk usage format")
        http.Error(w, "Unexpected disk usage format", http.StatusInternalServerError)
        return
    }
    diskUsed := diskLineParts[2]
    diskTotal := diskLineParts[7]

    // Parse Memory usage line
    memoryLineParts := strings.Fields(lines[1])
    if len(memoryLineParts) < 8 {
        log.Println("Unexpected memory usage format")
        http.Error(w, "Unexpected memory usage format", http.StatusInternalServerError)
        return
    }
    memoryUsed := memoryLineParts[2]
    memoryTotal := memoryLineParts[7]

    usage := SystemUsage{
        Disk: Usage{
            Total: diskTotal,
            Used:  diskUsed,
        },
        Memory: Usage{
            Total: memoryTotal,
            Used:  memoryUsed,
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
