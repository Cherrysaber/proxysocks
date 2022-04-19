package trojan

// AuthMethod trojan 认证方式接口
type AuthMethod interface {
	Method() string
	Auth(password string) bool
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

func (a *AuthPassword) Auth(password string) bool {
	_, ok := a.Map[password]
	return ok
}

func NewAuthPasswordSlice(slice []string) *AuthPassword {
	m := make(map[string]int, len(slice))
	for _, v := range slice {
		m[v] = 1
	}
	return &AuthPassword{
		Map: m,
	}
}

func NewAuthPasswordMap(m map[string]int) *AuthPassword {
	return &AuthPassword{
		Map: m,
	}
}
