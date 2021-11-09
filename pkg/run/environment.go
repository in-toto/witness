package run

import (
	"os"
	"os/user"
	"runtime"
	"strings"
)

type Environment struct {
	OS        string
	Hostname  string
	Username  string
	Variables map[string]string
}

func recordEnvironment() Environment {
	env := Environment{
		OS:        runtime.GOOS,
		Variables: make(map[string]string),
	}

	if hostname, err := os.Hostname(); err == nil {
		env.Hostname = hostname
	}

	if user, err := user.Current(); err == nil {
		env.Username = user.Username
	}

	variables := os.Environ()
	for _, v := range variables {
		parts := strings.SplitN(v, "=", 2)
		key := parts[0]
		val := ""
		if len(parts) > 1 {
			val = parts[1]
		}

		env.Variables[key] = val
	}

	return env
}
