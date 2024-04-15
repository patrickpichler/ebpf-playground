package tracer

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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

	index := uint32(0)

	fd := uint32(objs.tracerPrograms.TracepointDummyTailcall.FD())

	if err := objs.tracerMaps.TailcallMap.Update(&index, &fd, 0); err != nil {
		return err
	}

	_, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.tracerPrograms.TracepointRawSyscallsSysEnter,
	})
	if err != nil {
		return err
	}

	_, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: objs.tracerPrograms.TracepointRawSyscallsSysExit,
	})
	if err != nil {
		return err
	}

	return nil
}
