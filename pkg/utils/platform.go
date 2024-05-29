package utils

import (
	"os"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
)

const platformEnv = "PLATFORM"
const controlPlaneTopologyEnv = "CONTROL_PLANE_TOPOLOGY"

func GetPlatform() string {
	p := os.Getenv(platformEnv)
	if p == "" {
		return "OpenShift"
	}
	return p
}

func GetControlPlaneTopology() string {
	return os.Getenv(controlPlaneTopologyEnv)
}

func IsHostedControlPlane() bool {
	topology := GetControlPlaneTopology()
	if strings.EqualFold(topology, string(configv1.ExternalTopologyMode)) {
		return true
	} else {
		return false
	}
}
