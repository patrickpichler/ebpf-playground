package main

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"syscall"
	"time"

	"patrickpichler.dev/ebpf-playground/pkg/tracer"
)

func main() {
	t := tracer.NewTracer()
	if err := t.Init(); err != nil {
		log.Fatal(err)
	}

	// if err := t.Arm(); err != nil {
	// 	log.Fatal(err)
	// }

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()

	startDummyRun(ctx, t)
	// startDummyRun(ctx, t)
	// startDummyRun(ctx, t)
	// startDummyRun(ctx, t)
	// startDummyRun(ctx, t)
	// startDummyRun(ctx, t)

	if err := t.CloseFilters(); err != nil {
		fmt.Println("error during close:", err)
	}

	<-ctx.Done()

}

func startDummyRun(ctx context.Context, t *tracer.Tracer) {
	go func() {
	outer:
		for {
			select {
			case <-ctx.Done():
				break outer
			default:
			}

			if err := t.Dummy(); err != nil {
				fmt.Println("error:", err)
			}
			time.Sleep(1 * time.Millisecond)
		}
	}()
}
