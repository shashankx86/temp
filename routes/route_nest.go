// components/nestarg.go

package components

import (
    "encoding/json"
    "net/http"
    "os/exec"
    "regexp"
    "strings"
)

func GetNestResources(w http.ResponseWriter, r *http.Request) {
    output, err := executeCommand("nest", "resources")
    if err != nil {
        http.Error(w, "Error executing command: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Define regex patterns
    diskUsagePattern := regexp.MustCompile(`Disk usage: (\d+\.\d+) GB used out of (\d+\.\d+) GB limit`)
    memoryUsagePattern := regexp.MustCompile(`Memory usage: (\d+\.\d+) GB used out of (\d+\.\d+) GB limit`)

    // Extract disk usage
    diskMatches := diskUsagePattern.FindStringSubmatch(output)
    if len(diskMatches) != 3 {
        http.Error(w, "Unexpected disk usage format", http.StatusInternalServerError)
        return
    }

    // Extract memory usage
    memoryMatches := memoryUsagePattern.FindStringSubmatch(output)
    if len(memoryMatches) != 3 {
        http.Error(w, "Unexpected memory usage format", http.StatusInternalServerError)
        return
    }

    // Prepare JSON response
    resources := map[string]map[string]string{
        "Disk": {
            "Used":  diskMatches[1] + " GB",
            "Total": diskMatches[2] + " GB",
        },
        "Memory": {
            "Used":  memoryMatches[1] + " GB",
            "Total": memoryMatches[2] + " GB",
        },
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resources)
}

func executeCommand(command string, args ...string) (string, error) {
    out, err := exec.Command(command, args...).Output()
    if err != nil {
        return "", err
    }
    return string(out), nil
}
