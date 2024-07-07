// components/websocket_server.go

package components

import (
	"log"
	"net/http"
	"os/exec"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"github.com/go-chi/cors"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

var SHELL_TYPE = "bash"

func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade websocket: %v", err)
		return
	}
	defer conn.Close()

	var shell *exec.Cmd
	switch SHELL_TYPE {
	case "bash":
		shell = exec.Command("bash")
	case "tmux":
		shell, err = tmuxCommand()
		if err != nil {
			log.Printf("Failed to start tmux: %v", err)
			return
		}
	default:
		log.Printf("Unknown shell type: %s", SHELL_TYPE)
		return
	}

	ptyFile, err := pty.Start(shell)
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
	corsOptions := cors.Options{
		AllowedOrigins: []string{"*"},
	}
	corsMiddleware := cors.New(corsOptions).Handler

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		corsMiddleware(http.HandlerFunc(HandleWebSocket)).ServeHTTP(w, r)
	})

	log.Printf("WebSocket server is running on ws://localhost:5492 (Shell Type: %s)", SHELL_TYPE)
	log.Fatal(http.ListenAndServe(":5498", nil))
}

// tmuxCommand creates or attaches to a tmux session named 'nuc-rev'
func tmuxCommand() (*exec.Cmd, error) {
	// Check if tmux session 'nuc-rev' exists
	cmd := exec.Command("tmux", "has-session", "-t", "nuc-rev")
	err := cmd.Run()
	if err != nil {
		// Session does not exist, create a new one
		cmd = exec.Command("tmux", "new-session", "-s", "nuc-rev", "-d")
		if err := cmd.Run(); err != nil {
			return nil, err
		}
	}

	// Attach to the 'nuc-rev' tmux session
	return exec.Command("tmux", "attach-session", "-t", "nuc-rev"), nil
}
