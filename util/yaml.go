package util

import (
	"os"

	"github.com/Alonza0314/cert-go/logger"
	"gopkg.in/yaml.v3"
)

func ReadYamlFile(filePath string) (map[string]interface{}, error) {
	yamlFile, err := os.ReadFile(filePath)
	if err != nil {
		logger.Error("ReadYamlFile", err.Error())
		return nil, err
	}

	data := make(map[string]interface{})

	err = yaml.Unmarshal(yamlFile, &data)
	if err != nil {
		logger.Error("ReadYamlFile", err.Error())
		return nil, err
	}

	return data, nil
}

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
