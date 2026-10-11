package main

import (
	"context"
	"example.com/nearai-inference-example/internal/demo"
	"log"
	"time"
)

func main() {
	c, err := demo.Configuration(false)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if err = demo.RunIntegrated(ctx, c, false); err != nil {
		log.Fatal(err)
	}
}
