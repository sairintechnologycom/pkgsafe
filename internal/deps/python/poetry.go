package python

import "fmt"

func ParsePoetryLockFile(path string) ([]Dependency, error) {
	return nil, fmt.Errorf("poetry.lock scanning is designed but not implemented in this milestone")
}

func ParseUVLockFile(path string) ([]Dependency, error) {
	return nil, fmt.Errorf("uv.lock scanning is designed but not implemented in this milestone")
}
