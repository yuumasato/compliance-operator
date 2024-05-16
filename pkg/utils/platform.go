package utils

import (
	"os"
)

const platformEnv = "PLATFORM"

func GetPlatform() string {
	p := os.Getenv(platformEnv)
	if p == "" {
		return "OpenShift"
	}
	return p
}
