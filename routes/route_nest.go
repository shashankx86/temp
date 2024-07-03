package routes

import (
    "encoding/json"
    "net/http"
    "os/exec"
    "strings"
)

type SystemUsage struct {
    Disk    Usage `json:"disk"`
    Memory  Usage `json:"memory"`
}

type Usage struct {
    Total  string `json:"total"`
    Used   string `json:"used"`
}

func NestResourcesHandler(w http.ResponseWriter, r *http.Request) {
    cmd := exec.Command("sh", "-c", "nest resources")
    output, err := cmd.Output()
    if err != nil {
        http.Error(w, "Failed to execute command", http.StatusInternalServerError)
        return
    }

    lines := strings.Split(string(output), "\n")
    diskUsage := strings.Split(lines[1], ":")[1]
    memoryUsage := strings.Split(lines[2], ":")[1]

    diskParts := strings.Fields(diskUsage)
    memoryParts := strings.Fields(memoryUsage)

    usage := SystemUsage{
        Disk: Usage{
            Total: diskParts[4],
            Used:  diskParts[1],
        },
        Memory: Usage{
            Total: memoryParts[4],
            Used:  memoryParts[1],
        },
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(usage)
}
