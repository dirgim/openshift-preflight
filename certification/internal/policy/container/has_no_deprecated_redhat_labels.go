package container

import (
	cranev1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/redhat-openshift-ecosystem/openshift-preflight/certification"
	log "github.com/sirupsen/logrus"
)

var deprecatedRedHatLabels = []string{"INSTALL", "Architecture", "BZComponent", "Name", "Release", "UNINSTALL", "Version"}

// HasRequiredRedHatLabelsCheck evaluates the image manifest to ensure that the appropriate metadata
// labels are present on the image asset as it exists in its current container registry.
type HasNoDeprecatedRedHatLabels struct{}

func (p *HasNoDeprecatedRedHatLabels) Validate(imgRef certification.ImageReference) (bool, error) {
	labels, err := p.getDataForValidate(imgRef.ImageInfo)
	if err != nil {
		return false, err
	}

	return p.validate(labels)
}

func (p *HasNoDeprecatedRedHatLabels) getDataForValidate(image cranev1.Image) (map[string]string, error) {
	configFile, err := image.ConfigFile()
	return configFile.Config.Labels, err
}

func (p *HasNoDeprecatedRedHatLabels) validate(labels map[string]string) (bool, error) {
	deprecatedLabels := []string{}
	for _, label := range deprecatedRedHatLabels {
		if labels[label] != "" {
			deprecatedLabels = append(deprecatedLabels, label)
		}
	}

	if len(deprecatedLabels) > 0 {
		log.Warn("Deprecated labels are present:", deprecatedLabels)
	}

	return len(deprecatedLabels) == 0, nil
}

func (p *HasNoDeprecatedRedHatLabels) Name() string {
	return "HasNoDeprecatedRedHatLabels"
}

func (p *HasNoDeprecatedRedHatLabels) Metadata() certification.Metadata {
	return certification.Metadata{
		Description:      "Checking if the deprecated labels (INSTALL, Architecture, BZComponent, Name, Release, UNINSTALL, Version) are present in the container metadata.",
		Level:            "good",
		KnowledgeBaseURL: "https://connect.redhat.com/zones/containers/container-certification-policy-guide",
		CheckURL:         "https://connect.redhat.com/zones/containers/container-certification-policy-guide",
	}
}

func (p *HasNoDeprecatedRedHatLabels) Help() certification.HelpText {
	return certification.HelpText{
		Message:    "Check Check HasNoDeprecatedRedHatLabels encountered an error. Please review the preflight.log file for more information.",
		Suggestion: "Remove the following labels from your Dockerfile: INSTALL, Architecture, BZComponent, Name, Release, UNINSTALL, Version",
	}
}
