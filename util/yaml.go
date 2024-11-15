package util

import (
	"os"

	"github.com/Alonza0314/cert-go/logger"
	"gopkg.in/yaml.v3"
)

func ReadYamlFileToStruct(filePath string, v interface{}) error {
	yamlFile, err := os.ReadFile(filePath)
	if err != nil {
		logger.Error("ReadYamlFile", err.Error())
		return err
	}

	err = yaml.Unmarshal(yamlFile, v)
	if err != nil {
		logger.Error("ReadYamlFileToStruct", err.Error())
		return err
	}

	return nil
}
