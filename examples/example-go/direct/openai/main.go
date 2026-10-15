// Experimental direct endpoint integration with the official OpenAI Go client.
package main

import (
	"context"
	"log"
	"time"

	"example.com/nearai-inference-example/internal/demo"
)

func main() {
	c, err := demo.Configuration(true)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if err = demo.RunDirectOpenAI(ctx, c); err != nil {
		log.Fatal(err)
	}
}
