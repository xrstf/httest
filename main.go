package main

import (
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	log.Printf(`[%s] "%s %s" %s "%s"`, r.RemoteAddr, r.Method, r.URL, r.Proto, r.UserAgent())

	response, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Println(err)

		w.WriteHeader(500)
		response = []byte("Could not dump incoming request.\n")
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(response)
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

	port, err := strconv.Atoi(listenPort)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Listening on %s:%d …\n", listenOn, port)

	http.HandleFunc("/", handler)
	err = http.ListenAndServe(net.JoinHostPort(listenOn, strconv.Itoa(port)), nil)
	if err != nil {
		log.Fatal(err)
	}
}
