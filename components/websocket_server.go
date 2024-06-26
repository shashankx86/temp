package components

import (
    "log"
    "os"
    "os/exec"
    "strings"

    "github.com/creack/pty"
    "github.com/gorilla/websocket"
    "net/http"
)

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return true
    },
}

func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("Failed to upgrade websocket: %v", err)
        return
    }
    defer conn.Close()

    var shell *exec.Cmd
    var ptyFile *os.File

    existingSessions, err := exec.Command("tmux", "ls").Output()
    if err == nil && strings.Contains(string(existingSessions), "ncwi-shell") {
        shell = exec.Command("tmux", "attach-session", "-t", "ncwi-shell")
    } else {
        shell = exec.Command("tmux", "new-session", "-s", "ncwi-shell")
    }

    ptyFile, err = pty.Start(shell)
    if err != nil {
        log.Printf("Failed to start pty: %v", err)
        return
    }
    defer ptyFile.Close()

    go func() {
        buf := make([]byte, 1024)
        for {
            n, err := ptyFile.Read(buf)
            if err != nil {
                return
            }
            conn.WriteMessage(websocket.TextMessage, buf[:n])
        }
    }()

    for {
        _, msg, err := conn.ReadMessage()
        if err != nil {
            break
        }
        ptyFile.Write(msg)
    }
}

func StartWebSocketServer() {
    http.HandleFunc("/ws", HandleWebSocket)
    log.Println("WebSocket server is running on ws://localhost:5492")
    log.Fatal(http.ListenAndServe(":5492", nil))
}
