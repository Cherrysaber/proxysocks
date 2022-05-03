package trojan

import "io"

// AuthMethod trojan 认证方式接口
type AuthMethod interface {
	Method() string
	Auth(r io.Reader) error
}

type AuthFailure string

func (a AuthFailure) Error() string {
	return "AuthFailure"
}

type AuthPassword struct {
	Map map[string]int
}

func (a *AuthPassword) Method() string {
	return "password"
}

func (a *AuthPassword) Auth(r io.Reader) error {
	buf := make([]byte, 56, 56)
	if n, err := io.ReadFull(r, buf); err != nil {
		if n != 0 {
			err = AuthFailure(buf[:n])
		}
		return err
	}
	if _, ok := a.Map[string(buf)]; !ok {
		return AuthFailure(buf)
	}
	return nil
}

func NewAuthPasswordSlice(slice []string, toHash bool) *AuthPassword {
	m := make(map[string]int, len(slice))
	for _, v := range slice {
		if toHash {
			m[string(sha224(v))] = 1
		} else {
			m[v] = 1
		}

	}
	return &AuthPassword{
		Map: m,
	}
}

func NewAuthPasswordMap(m map[string]int, toHash bool) *AuthPassword {
	if toHash {
		Map := make(map[string]int, len(m))
		for k, v := range m {
			Map[string(sha224(k))] = v
		}
		m = Map
	}
	return &AuthPassword{
		Map: m,
	}
}
