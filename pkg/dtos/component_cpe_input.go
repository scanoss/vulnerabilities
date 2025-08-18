package dtos

type ComponentCPESRequestDTO struct {
	Component Component `json:"component"`
}

type Component struct {
	Purl        string `json:"purl"`
	Requirement string `json:"requirement,omitempty"`
}
