// components/websocket_server.go

package components

import (
	"log"
	"net/http"
	"os/exec"

	"github.com/creack/pty"
	socketio "github.com/googollee/go-socket.io"
	"github.com/go-chi/cors"
)

var SHELL_TYPE = "bash"

func HandleSocketIO(server socketio.Server) {
	server.OnConnect("/", func(s socketio.Conn) error {
		s.SetContext("")
		log.Printf("Connected: %s", s.ID())

		var shell *exec.Cmd
		var err error
		switch SHELL_TYPE {
		case "bash":
			shell = exec.Command("bash")
		case "tmux":
			shell, err = tmuxCommand()
			if err != nil {
				log.Printf("Failed to start tmux: %v", err)
				s.Close()
				return err
			}
		default:
			log.Printf("Unknown shell type: %s", SHELL_TYPE)
			s.Close()
			return nil
		}

		ptyFile, err := pty.Start(shell)
		if err != nil {
			log.Printf("Failed to start pty: %v", err)
			s.Close()
			return err
		}
		defer ptyFile.Close()

		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := ptyFile.Read(buf)
				if err != nil {
					return
				}
				s.Emit("output", string(buf[:n]))
			}
		}()

		s.On("input", func(msg string) {
			ptyFile.Write([]byte(msg))
		})

		s.OnDisconnect(func(reason string) {
			log.Printf("Disconnected: %s", reason)
		})

		return nil
	})
}

func StartWebSocketServer() {
	server := socketio.NewServer(nil)

	HandleSocketIO(*server)

	server.OnError("/", func(s socketio.Conn, e error) {
		log.Printf("Error: %v", e)
	})

	corsOptions := cors.Options{
		AllowedOrigins: []string{"*"},
	}
	corsMiddleware := cors.New(corsOptions).Handler

	mux := http.NewServeMux()
	mux.Handle("/socket.io/", corsMiddleware(server))
	mux.Handle("/", http.FileServer(http.Dir("./public")))

	log.Printf("WebSocket server is running on ws://localhost:5498 (Shell Type: %s)", SHELL_TYPE)
	log.Fatal(http.ListenAndServe(":5498", mux))
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
