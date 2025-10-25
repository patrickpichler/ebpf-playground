.PHONY: gen-bpf
gen-bpf:
	go generate ./pkg/tracer/

gen-compile-commands:
	@bear --force-wrapper -- make gen-bpf
