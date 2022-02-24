package container

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
    "crypto/tls"

    cranev1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/redhat-openshift-ecosystem/openshift-preflight/certification"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// apiRespondData is the response received from the defined API
type apiRepositoryResponseData struct {
	Id                       string   `json:"_id"`
	CreateDate               string   `json:"creation_date"`
	LastUpdateTime           string   `json:"last_update_date"`
	ReleaseCategories        []string `json:"release_categories"`
	ReplacedByRepositoryName string `json:"replaced_by_repository_name"`
}

// IsntDeprecatedImageCheck finds the repository name as defined in the images 'name' label
// and checks it against Red Hat APIs to confirm that the repository is not deprecated
type IsNotDeprecatedImageCheck struct{}

func (p *IsNotDeprecatedImageCheck) Validate(imgRef certification.ImageReference) (bool, error) {
	imageNameLabel, err := p.getImageNameLabel(imgRef.ImageInfo)
    if err != nil {
        return false, err
    }

	log.Debugf("image repository name is %s", imageNameLabel)

	var pyxisRepositoryURL = viper.GetString("pyxis_host") + pyxisRepositoryEndpoint

	req, err := p.buildRepositoryRequest(pyxisRepositoryURL, imageNameLabel)
	if err != nil {
		log.Error("unable to build API request structure", err)
		return false, err
	}

	resp, err := p.queryAPI(req)
	if err != nil {
		log.Error("unable to query repository API for deprecated image check", err)
		return false, err
	}

	data, err := p.parseAPIResponse(resp)
	if err != nil {
		log.Error("unable to parse response provided by repository API", err)
		return false, err
	}

	return p.validate(data)
}

func (p *IsNotDeprecatedImageCheck) getImageNameLabel(image cranev1.Image) (string, error) {
	configFile, err := image.ConfigFile()
	return configFile.Config.Labels["name"], err
}

// buildRepositoryRequest builds the http.Request using the input parameters and returns a client.
func (p *IsNotDeprecatedImageCheck) buildRepositoryRequest(repositoryEndpoint, imageNameLabel string) (*http.Request, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s", repositoryEndpoint, imageNameLabel), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// queryAPI uses the provided client to query the remote API, and returns the response if it
// response is successful, or an error if the response was unexpected in any way.
func (p *IsNotDeprecatedImageCheck) queryAPI(request *http.Request) (*http.Response, error) {
    var pyxisCertificate = viper.GetString("pyxis_cert")
    var pyxisCertificateKey = viper.GetString("pyxis_cert_key")

    cert, _ := tls.LoadX509KeyPair(pyxisCertificate, pyxisCertificateKey)

    ssl := &tls.Config{
        Certificates:       []tls.Certificate{cert},
        InsecureSkipVerify: true,
    }

    client := &http.Client{
            Transport: &http.Transport{
                TLSClientConfig: ssl,
            },
        }
	log.Trace("making API request to ", request.URL.String())
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	log.Trace("response code: ", resp.Status)

	// The Connect API returns a 200 if the repository was found and 404 if it wasn't.
	// Anything else is considered an error
	if resp.StatusCode != 200 && resp.StatusCode != 404 {
		return nil, fmt.Errorf("received an unexpected status code for the request: %s", resp.Status)
	}

	return resp, nil
}

// parseAPIResponse reads the response and checks the body for the expected contents, and then
// returns the body content as apiRepositoryResponseData.
func (p *IsNotDeprecatedImageCheck) parseAPIResponse(resp *http.Response) (*apiRepositoryResponseData, error) {
	var data apiRepositoryResponseData
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	log.Trace("response body: ", string(body))

	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

// validate checks the apiRepositoryResponseData and confirms that the package is unique by confirming that the
// API returned no packages using the same name.
func (p *IsNotDeprecatedImageCheck) validate(resp *apiRepositoryResponseData) (bool, error) {
	var isNotDeprecated = true
	log.Trace("repository release categories: ", resp.ReleaseCategories)
	if len(resp.ReleaseCategories) == 0 {
		return false, nil
	} else {
		for _, category := range resp.ReleaseCategories {
			if category == "Deprecated" {
			    isNotDeprecated = false
			}
		}
	}

	if !isNotDeprecated {
		log.Warn("The image repository is deprecated")
		if resp.ReplacedByRepositoryName != "" {
		    log.Info("The image repository is replaced by ", resp.ReplacedByRepositoryName)
		}
	}

	return isNotDeprecated, nil
}

func (p *IsNotDeprecatedImageCheck) Name() string {
	return "IsNotDeprecatedImage"
}

func (p *IsNotDeprecatedImageCheck) Metadata() certification.Metadata {
	return certification.Metadata{
		Description:      "Checking if the image is deprecated",
		Level:            "best",
		KnowledgeBaseURL: "https://sdk.operatorframework.io/docs/olm-integration/tutorial-bundle/",
		CheckURL:         "https://sdk.operatorframework.io/docs/olm-integration/tutorial-bundle/",
	}
}

func (p *IsNotDeprecatedImageCheck) Help() certification.HelpText {
	return certification.HelpText{
		Message:    "Check encountered an error. It is possible that the image's repository is deprecated.",
		Suggestion: "The image's repository must not have the 'Deprecated' entry in its release_categories section.",
	}
}

// apiClient is a simple interface encompassing the only http.Client method we utilize for preflight checks. This exists to
// enable mock implementations for testing purposes.
type apiClient interface {
	Do(req *http.Request) (*http.Response, error)
}
