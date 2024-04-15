package tracer

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -no-global-types -cc clang-14 -target arm64 tracer ./c/tracer.bpf.c -- -I./c/headers -Wno-address-of-packed-member -O2 -g

func (t *Tracer) Arm() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	spec, err := loadTracer()
	if err != nil {
		return err
	}

	var objs tracerObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps:            ebpf.MapOptions{},
		Programs:        ebpf.ProgramOptions{},
		MapReplacements: map[string]*ebpf.Map{},
	}); err != nil {
		return err
	}

	t.objs = &objs

	return nil
}
