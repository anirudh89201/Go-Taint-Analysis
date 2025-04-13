package main

import (
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		queryInput := r.URL.Query().Get("input") // Source 1
		formInput := r.FormValue("formField")    // Source 2

		// Sinks
		w.Write([]byte(queryInput)) // want "potential XSS"
		w.Write([]byte(formInput))  // want "potential XSS"
	})
	http.ListenAndServe(":8080", nil)
}
