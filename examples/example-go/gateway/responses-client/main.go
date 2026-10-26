package main

import (
	"context"
	"log"
	"time"

	"example.com/nearai-inference-example/internal/demo"
)

func run() error {
	c, err := demo.ConfigurationForModel(false, "z-ai/glm-5.3-flash")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return demo.RunEndpoint(ctx, c, false)
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
