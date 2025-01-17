package pyxis

type CertImage struct {
	ID                     string       `json:"_id,omitempty"`
	Certified              bool         `json:"certified" default:"false"`
	Deleted                bool         `json:"deleted" default:"false"`
	DockerImageDigest      string       `json:"docker_image_digest,omitempty"`
	DockerImageID          string       `json:"docker_image_id,omitempty"`
	ImageID                string       `json:"image_id,omitempty"`
	ISVPID                 string       `json:"isv_pid,omitempty"`
	ParsedData             *ParsedData  `json:"parsed_data,omitempty"`
	RawConfig              string       `json:"raw_config,omitempty"`
	Repositories           []Repository `json:"repositories,omitempty"`
	SumLayerSizeBytes      int64        `json:"sum_layer_size_bytes,omitempty"`
	UncompressedTopLayerId string       `json:"uncompressed_top_layer_id,omitempty"` //TODO: figure out how to populate this, it is not required
}

type ParsedData struct {
	Architecture           string  `json:"architecture,omitempty"`
	Command                string  `json:"command,omitempty"`
	Comment                string  `json:"comment,omitempty"`
	Container              string  `json:"container,omitempty"`
	Created                string  `json:"created,omitempty"`
	DockerVersion          string  `json:"docker_version,omitempty"`
	ImageID                string  `json:"image_id,omitempty"`
	Labels                 []Label `json:"labels,omitempty"` // required
	OS                     string  `json:"os,omitempty"`
	Ports                  string  `json:"ports,omitempty"`
	Size                   int64   `json:"size,omitempty"`
	UncompressedLayerSizes []Layer `json:"uncompressed_layer_sizes,omitempty"` //TODO: figure out how to populate this its required
}

type Repository struct {
	Published  bool   `json:"published" default:"false"`
	PushDate   string `json:"push_date,omitempty"` // time.Now
	Registry   string `json:"registry,omitempty"`
	Repository string `json:"repository,omitempty"`
	Tags       []Tag  `json:"tags,omitempty"`
}

type Label struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Tag struct {
	AddedDate string `json:"added_date,omitempty"` // time.Now
	Name      string `json:"name,omitempty"`
}

type RPMManifest struct {
	ID      string `json:"_id,omitempty"`
	ImageID string `json:"image_id,omitempty"`
	RPMS    []RPM  `json:"rpms,omitempty"`
}

type RPM struct {
	Architecture string `json:"architecture,omitempty"`
	Gpg          string `json:"gpg,omitempty"`
	Name         string `json:"name,omitempty"`
	Nvra         string `json:"nvra,omitempty"`
	Release      string `json:"release,omitempty"`
	SrpmName     string `json:"srpm_name,omitempty"`
	SrpmNevra    string `json:"srpm_nevra,omitempty"`
	Summary      string `json:"summary,omitempty"`
	Version      string `json:"version,omitempty"`
}

type CertProject struct {
	ID                  string    `json:"_id,omitempty"`
	CertificationStatus string    `json:"certification_status" default:"In Progress"`
	Container           Container `json:"container"`
	Name                string    `json:"name"`                      // required
	ProjectStatus       string    `json:"project_status"`            // required
	Type                string    `json:"type" default:"Containers"` // required
	OsContentType       string    `json:"os_content_type,omitempty"`
}

type Container struct {
	DockerConfigJSON string `json:"docker_config_json"`
	Type             string `json:"type " default:"Containers"` // conditionally required
}

type Layer struct {
	LayerId string `json:"layer_id"`
	Size    int64  `json:"size_bytes"`
}

type TestResults struct {
	ID                string      `json:"_id,omitempty"`
	CertProject       string      `json:"cert_project"`       // TODO: see if this should be populated, if so with what?
	CertificationHash string      `json:"certification_hash"` // TODO: see if this should be populated, if so with what?
	Image             string      `json:"image"`
	OrgID             int         `json:"org_id"`
	Passed            bool        `json:"passed"`
	Results           Results     `json:"results"`
	TestLibrary       TestLibrary `json:"test_library"`
	Version           string      `json:"version"` // TODO: see if this should be populated, if so with what?
	ImageID           string      `json:"image_id"`
}

type Errors struct {
	CheckURL         string `json:"check_url"`
	Description      string `json:"description"`
	ElapsedTime      int    `json:"elapsed_time"`
	Help             string `json:"help"`
	KnowledgeBaseURL string `json:"knowledgebase_url"`
	Name             string `json:"name"`
	Suggestion       string `json:"suggestion"`
}

type Failed struct {
	CheckURL         string `json:"check_url"`
	Description      string `json:"description"`
	ElapsedTime      int    `json:"elapsed_time"`
	Help             string `json:"help"`
	KnowledgeBaseURL string `json:"knowledgebase_url"`
	Name             string `json:"name"`
	Suggestion       string `json:"suggestion"`
}

type Passed struct {
	CheckURL         string `json:"check_url"`
	Description      string `json:"description"`
	ElapsedTime      int    `json:"elapsed_time"`
	Help             string `json:"help"`
	KnowledgeBaseURL string `json:"knowledgebase_url"`
	Name             string `json:"name"`
	Suggestion       string `json:"suggestion"`
}

type Results struct {
	Errors []Errors `json:"errors"`
	Failed []Failed `json:"failed"`
	Passed []Passed `json:"passed"`
}

type TestLibrary struct {
	Commit  string `json:"commit"`
	Name    string `json:"name"`
	Version string `json:"version"`
}
