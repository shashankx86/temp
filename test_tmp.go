package main

import (
    "log"
    "net/http"

    "github.com/gorilla/mux"
    "napi/routes"
)

func main() {
    router := mux.NewRouter()
    routes.NestHandler(router)

    log.Println("Server is running on port 8080")
    if err := http.ListenAndServe(":8089", router); err != nil {
        log.Fatalf("Could not start server: %s\n", err.Error())
    }
}
