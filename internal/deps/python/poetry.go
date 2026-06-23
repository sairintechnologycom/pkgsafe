package python

import "fmt"

func ParsePoetryLockFile(path string) ([]Dependency, error) {
	return nil, fmt.Errorf("poetry.lock scanning is designed but not implemented in this milestone")
}

func ParseUVLockFile(path string) ([]Dependency, error) {
	return nil, fmt.Errorf("uv.lock scanning is designed but not implemented in this milestone")
}

func ParsePipfile(path string) ([]Dependency, error) {
	return nil, fmt.Errorf("Pipfile scanning is designed but not implemented in this milestone")
}

func ParsePipfileLock(path string) ([]Dependency, error) {
	return nil, fmt.Errorf("Pipfile.lock scanning is designed but not implemented in this milestone")
}

func ParseCondaEnvFile(path string) ([]Dependency, error) {
	return nil, fmt.Errorf("conda environment.yml scanning is designed but not implemented in this milestone")
}
