package shadowsocks

type ssError struct {
	prefix string
	op     string
	err    error
}

func (e *ssError) Error() string {
	if e == nil {
		return "<nil>"
	}
	s := e.prefix
	if e.op != "" {
		s += " " + e.op
	}
	if e.err != nil {
		s += ": " + e.err.Error()
	}
	return s
}

func (e *ssError) Unwrap() error {
	return e.err
}
