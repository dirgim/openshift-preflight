package container

import (
	"time"
)

var (
	checkContainerTimeout time.Duration = 10 * time.Second
	waitContainer         time.Duration = 2 * time.Second
)

const (
	// repositoryEndpoint is the endpoint used to query for repository information.
	// All Red Hat containers use the value of 'registry.access.redhat.com'
	// Partner containers use the value of 'registry.connect.redhat.com'.
	pyxisRepositoryEndpoint = "/v1/repositories/registry/registry.access.redhat.com/repository"
)
