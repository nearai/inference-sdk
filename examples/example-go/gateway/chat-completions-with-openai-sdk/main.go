// The official OpenAI Go client uses NEAR AI's verified HTTP transport.
package main

import (
	"context"
	"log"
	"time"

	"example.com/nearai-inference-example/internal/demo"
)

func main() {
	c, err := demo.Configuration(false)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if err = demo.RunOpenAI(ctx, c); err != nil {
		log.Fatal(err)
	}
}
