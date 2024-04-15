// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadTracer returns the embedded CollectionSpec for tracer.
func loadTracer() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TracerBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tracer: %w", err)
	}

	return spec, err
}

// loadTracerObjects loads tracer and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tracerObjects
//	*tracerPrograms
//	*tracerMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTracerObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTracer()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tracerSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracerSpecs struct {
	tracerProgramSpecs
	tracerMapSpecs
}

// tracerSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracerProgramSpecs struct {
	TracepointRawSyscallsSysEnter *ebpf.ProgramSpec `ebpf:"tracepoint__raw_syscalls__sys_enter"`
	TracepointRawSyscallsSysExit  *ebpf.ProgramSpec `ebpf:"tracepoint__raw_syscalls__sys_exit"`
	TracepointDummyTailcall       *ebpf.ProgramSpec `ebpf:"tracepoint_dummy_tailcall"`
}

// tracerMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracerMapSpecs struct {
	ContextMap  *ebpf.MapSpec `ebpf:"context_map"`
	TailcallMap *ebpf.MapSpec `ebpf:"tailcall_map"`
}

// tracerObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracerObjects struct {
	tracerPrograms
	tracerMaps
}

func (o *tracerObjects) Close() error {
	return _TracerClose(
		&o.tracerPrograms,
		&o.tracerMaps,
	)
}

// tracerMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracerMaps struct {
	ContextMap  *ebpf.Map `ebpf:"context_map"`
	TailcallMap *ebpf.Map `ebpf:"tailcall_map"`
}

func (m *tracerMaps) Close() error {
	return _TracerClose(
		m.ContextMap,
		m.TailcallMap,
	)
}

// tracerPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracerPrograms struct {
	TracepointRawSyscallsSysEnter *ebpf.Program `ebpf:"tracepoint__raw_syscalls__sys_enter"`
	TracepointRawSyscallsSysExit  *ebpf.Program `ebpf:"tracepoint__raw_syscalls__sys_exit"`
	TracepointDummyTailcall       *ebpf.Program `ebpf:"tracepoint_dummy_tailcall"`
}

func (p *tracerPrograms) Close() error {
	return _TracerClose(
		p.TracepointRawSyscallsSysEnter,
		p.TracepointRawSyscallsSysExit,
		p.TracepointDummyTailcall,
	)
}

func _TracerClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed tracer_arm64_bpfel.o
var _TracerBytes []byte
