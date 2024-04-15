.PHONY: gen-bpf
gen-bpf:
	go generate ./pkg/tracer/
