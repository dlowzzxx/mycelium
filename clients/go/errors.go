package mycelium

import "fmt"

type ProtocolError struct {
	Code                          string
	Message                       string
	HTTPStatus                    int
	EffectID                      EffectID
	RetryClassification           string
	StateMayHaveChanged           bool
	ProviderEffectMayHaveHappened bool
	Details                       any
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("mycelium protocol error %s: %s", e.Code, e.Message)
}

type TransportError struct {
	Operation                     string
	StateMayHaveChanged           bool
	ProviderEffectMayHaveHappened bool
	Cause                         error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("mycelium transport error during %s: state may have changed", e.Operation)
}
func (e *TransportError) Unwrap() error { return e.Cause }
