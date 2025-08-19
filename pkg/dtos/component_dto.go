package dtos

type ComponentDTO struct {
	Purl        string `json:"purl"`
	Requirement string `json:"requirement,omitempty"`
}
