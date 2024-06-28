// components/websocket_server.go

package components

import (
	"log"
	"net/http"
	"os/user"
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

func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade websocket: %v", err)
		return
	}
	defer conn.Close()

	shell := exec.Command("bash")
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
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("Error getting current user: %v", err)
	}
	serverUsername := currentUser.Username

	corsOptions := cors.Options{
		AllowedOrigins:   []string{"https://ncwi." + serverUsername + ".hackclub.app", "http://localhost"},
	}

	corsMiddleware := cors.New(corsOptions).Handler

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		corsMiddleware(http.HandlerFunc(HandleWebSocket)).ServeHTTP(w, r)
	})

	log.Println("WebSocket server is running on ws://localhost:5492")
	log.Fatal(http.ListenAndServe(":5492", nil))
}