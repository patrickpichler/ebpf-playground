package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"patrickpichler.dev/ebpf-playground/pkg/tracer"
)

func main() {
	t := tracer.NewTracer()
	if err := t.Arm(); err != nil {
		log.Fatal(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	fmt.Println("Waiting...")
	// Block until a signal is received.
	s := <-c
	fmt.Println("Got signal:", s)
}
