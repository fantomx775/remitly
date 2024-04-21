package main

import (
    "errors"
	"encoding/json"
	"fmt"
	"io/ioutil"
)

func verifyIAMRolePolicy(data map[string]interface{}) (bool, error) {
    policyDocument, ok := data["PolicyDocument"].(map[string]interface{})
    if !ok {
        return false, errors.New("PolicyDocument is not a dictionary")
    }

    statements, ok := policyDocument["Statement"].([]interface{})
    if !ok {
        return false, errors.New("Statement field is not a list")
    }

    if len(statements) == 0 {
        return false, errors.New("Statement field is empty")
    }

    for _, statement := range statements {
        statementMap, ok := statement.(map[string]interface{})
        if !ok {
            return false, errors.New("Statement is not a dictionary")
        }

        resource, ok := statementMap["Resource"].(string)
        if !ok {
            return false, errors.New("Resource field is missing or not a string")
        } else if resource == "*" {
            return false, nil
        }
    }

    return true, nil
}

func readJSONsFromFile(jsonFile string) bool {
	fileData, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		fmt.Printf("File '%s' not found.\n", jsonFile)
		return false
	}

	var data map[string]interface{}
	if err := json.Unmarshal(fileData, &data); err != nil {
		fmt.Printf("Invalid JSON format in file '%s': %s\n", jsonFile, err)
		return false
	}

	result, err := verifyIAMRolePolicy(data)
    if err != nil {
        fmt.Printf("Error: %s\n", err)
    } else {
        return result
    }
    return result

}

func main() {
	jsonFiles := []string{"iam.json"}
	for _, jsonFile := range jsonFiles {
		fmt.Printf("Verifying %s:\n", jsonFile)
		fmt.Println(readJSONsFromFile(jsonFile))
		fmt.Println()
	}
}
