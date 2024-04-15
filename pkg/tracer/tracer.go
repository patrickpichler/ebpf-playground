package tracer

type Tracer struct {
	objs *tracerObjects
}

func NewTracer() *Tracer {
	return &Tracer{}
}
