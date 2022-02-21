package container

import (
	cranev1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/redhat-openshift-ecosystem/openshift-preflight/certification"
	log "github.com/sirupsen/logrus"
)

var requiredRedHatLabels = []string{"com.redhat.component", "vendor", "name", "version", "release", "description",
"io.k8s.description", "vcs-ref", "vcs-type", "architecture", "com.redhat.build-host", "url", "build-date", "distribution-scope"}

// HasRequiredRedHatLabelsCheck evaluates the image manifest to ensure that the appropriate metadata
// labels are present on the image asset as it exists in its current container registry.
type HasRequiredRedHatLabelsCheck struct{}

func (p *HasRequiredRedHatLabelsCheck) Validate(imgRef certification.ImageReference) (bool, error) {
	labels, err := p.getDataForValidate(imgRef.ImageInfo)
	if err != nil {
		return false, err
	}

	return p.validate(labels)
}

func (p *HasRequiredRedHatLabelsCheck) getDataForValidate(image cranev1.Image) (map[string]string, error) {
	configFile, err := image.ConfigFile()
	return configFile.Config.Labels, err
}

func (p *HasRequiredRedHatLabelsCheck) validate(labels map[string]string) (bool, error) {
	missingLabels := []string{}
	for _, label := range requiredRedHatLabels {
		if labels[label] == "" {
			missingLabels = append(missingLabels, label)
		}
	}

	if len(missingLabels) > 0 {
		log.Warn("expected labels are missing:", missingLabels)
	}

	return len(missingLabels) == 0, nil
}

func (p *HasRequiredRedHatLabelsCheck) Name() string {
	return "HasRequiredRedHatLabel"
}

func (p *HasRequiredRedHatLabelsCheck) Metadata() certification.Metadata {
	return certification.Metadata{
		Description:      "Checking if the required labels (com.redhat.component, vendor, name, version, release, description, io.k8s.description, vcs-ref, vcs-type, architecture, com.redhat.build-host, url, build-date, distribution-scope) are present in the container metadata.",
		Level:            "good",
		KnowledgeBaseURL: "https://connect.redhat.com/zones/containers/container-certification-policy-guide",
		CheckURL:         "https://connect.redhat.com/zones/containers/container-certification-policy-guide",
	}
}

func (p *HasRequiredRedHatLabelsCheck) Help() certification.HelpText {
	return certification.HelpText{
		Message:    "Check Check HasRequiredRedHatLabelsCheck encountered an error. Please review the preflight.log file for more information.",
		Suggestion: "Add the following labels to your Dockerfile or Containerfile: com.redhat.component, vendor, name, version, release, description, io.k8s.description, vcs-ref, vcs-type, architecture, com.redhat.build-host, url, build-date, distribution-scope",
	}
}
