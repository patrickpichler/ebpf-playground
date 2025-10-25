package tracer

import (
	"math/rand"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -no-global-types -target arm64 tracer ./c/tracer.bpf.c -- -I./c/headers -Wno-address-of-packed-member -O2 -g

func (t *Tracer) Arm() error {
	if err := t.Init(); err != nil {
		return err
	}

	index := uint32(0)

	objs := t.objs

	fd := uint32(objs.tracerPrograms.TracepointDummyTailcall.FD())

	if err := objs.tracerMaps.TailcallMap.Update(&index, &fd, 0); err != nil {
		return err
	}

	if _, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.tracerPrograms.TracepointRawSyscallsSysEnter,
	}); err != nil {
		return err
	}

	if _, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: objs.tracerPrograms.TracepointRawSyscallsSysExit,
	}); err != nil {
		return err
	}

	return nil
}

func (t *Tracer) Init() error {
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

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func (t *Tracer) Dummy() error {
	val := RandStringBytes(rand.Intn(250)) + ".scope"

	padded := make([]byte, 256)
	copy(padded, val)

	err := t.objs.Filters.Update(padded, uint8(0), ebpf.UpdateAny)
	return err
}

func (t*Tracer) CloseFilters()error {
	return t.objs.Filters.Close()
}
