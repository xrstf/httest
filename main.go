package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
)

func newHandler(instance string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if instance != "" {
			log.Printf(`[%s] [%s] "%s %s" %s "%s"`, instance, r.RemoteAddr, r.Method, r.URL, r.Proto, r.UserAgent())
		} else {
			log.Printf(`[%s] "%s %s" %s "%s"`, r.RemoteAddr, r.Method, r.URL, r.Proto, r.UserAgent())
		}

		response, err := httputil.DumpRequest(r, true)
		if err != nil {
			log.Println(err)

			w.WriteHeader(500)
			response = []byte("Could not dump incoming request.\n")
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(response)

		if instance != "" {
			w.Write([]byte(fmt.Sprintf("Instance: %s\n", instance)))
		}
	}
}

func main() {
	listenOn := os.Getenv("LISTEN_HOST")
	if len(listenOn) == 0 {
		listenOn = "0.0.0.0"
	}

	listenPort := os.Getenv("LISTEN_PORT")
	if len(listenPort) == 0 {
		listenPort = "8080"
	}

	instance := os.Getenv("INSTANCE")

	port, err := strconv.Atoi(listenPort)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Listening on %s:%d …\n", listenOn, port)

	http.HandleFunc("/", newHandler(instance))
	err = http.ListenAndServe(net.JoinHostPort(listenOn, strconv.Itoa(port)), nil)
	if err != nil {
		log.Fatal(err)
	}
}
