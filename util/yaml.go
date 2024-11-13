package util

import (
	"os"

	"github.com/Alonza0314/cert-go/logger"
	"gopkg.in/yaml.v3"
)

func ReadYamlFile(filePath string) (map[string]interface{}, error) {
	yamlFile, err := os.ReadFile(filePath)
	if err != nil {
		logger.Error("read yaml file error: " + err.Error())
		return nil, err
	}

	data := make(map[string]interface{})

	err = yaml.Unmarshal(yamlFile, &data)
	if err != nil {
		logger.Error("parse yaml file error: " + err.Error())
		return nil, err
	}

	return data, nil
}
