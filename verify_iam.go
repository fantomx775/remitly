package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

func checkPolicyDocumentFields(data map[string]interface{}) (bool, error) {
	requiredFields := map[string]bool{
		"Version":   true,
		"Statement": true,
	}

	for field := range requiredFields {
		if _, ok := data[field]; !ok {
			return false, errors.New(field + " field is missing")
		}
	}

	return true, nil
}

func checkStatementFields(data map[string]interface{}) (bool, error) {
	requiredFields := map[string]bool{
		"Effect":   true,
		"Action":   true,
		"Resource": true,
	}

	for field := range requiredFields {
		if _, ok := data[field]; !ok {
			return false, errors.New(field + " field is missing")
		}
	}

	return true, nil
}

func checkActionField(data map[string]interface{}) (bool, error) {
	action, _ := data["Action"]

	switch act := action.(type) {
	case []interface{}:
		if len(act) == 0 {
			return false, errors.New("Action field is empty")
		}
		for _, a := range act {
			if _, ok := a.(string); !ok {
				return false, errors.New("Action field contains non-string value")
			}
		}
	default:
		return false, errors.New("Action field is not a string or a list")
	}

	return true, nil
}

func checkEffectField(data map[string]interface{}) (bool, error) {
	effect, ok := data["Effect"].(string)
	if !ok {
		return false, errors.New("Effect field is not a string")
	}

	if effect != "Allow" && effect != "Deny" {
		return false, errors.New("Effect field is not 'Allow' or 'Deny'")
	}

	return true, nil
}

func checkVersion(data map[string]interface{}) (bool, error) {
	version, ok := data["Version"].(string)
	if !ok {
		return false, errors.New("Version field is not a string")
	}

	if version != "2012-10-17" && version != "2008-10-17" {
		return false, errors.New("Version field is not '2012-10-17' neither '2008-10-17'")
	}

	return true, nil
}

func verifyIAMRolePolicy(data map[string]interface{}) (bool, error) {

	policyDocument, ok := data["PolicyDocument"].(map[string]interface{})
	astrix := true
	if !ok {
		return false, errors.New("PolicyDocument is not a dictionary")
	}
	ok, err := checkPolicyDocumentFields(policyDocument)
	if !ok {
		return false, err
	}
	ok, err = checkVersion(policyDocument)
	if !ok {
		return false, err
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

		ok, err := checkStatementFields(statementMap)
		if !ok {
			return false, err
		}
		ok, err = checkActionField(statementMap)
		if !ok {
			return false, err
		}
		ok, err = checkEffectField(statementMap)
		if !ok {
			return false, err
		}
		_, ok = statementMap["Principal"]
		if ok {
			return false, errors.New("Principal field is not allowed")
		}

		resource, ok := statementMap["Resource"]

		switch res := resource.(type) {
		case string:
			if res == "*" {
				astrix = false
			}
		case []interface{}:
			for _, res := range res {
				if r, ok := res.(string); ok {
					if r == "*" {
						astrix = false
						break
					}
				} else {
					return false, errors.New("Resource list contains non-string value")
				}
			}
		default:
			return false, errors.New("Resource field is not a string or a list")
		}
	}

	return astrix, nil
}

func readJSONsFromFile(jsonFile string) (bool, error) {
	fileData, err := os.ReadFile(jsonFile)
	if err != nil {
		fmt.Printf("File '%s' not found.\n", jsonFile)
		return false, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(fileData, &data); err != nil {
		fmt.Printf("Invalid JSON format in file '%s': %s\n", jsonFile, err)
		return false, err
	}

	result, err := verifyIAMRolePolicy(data)
	return result, err
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run verify_iam.go <path_to_json_file>")
		return
	}

	jsonFile := os.Args[1]

	fmt.Printf("\nVerifying file: %s\n", jsonFile)
	result, err := readJSONsFromFile(jsonFile)
	if err != nil {
		fmt.Printf("Error: %s\n\n", err)
	} else {
		fmt.Printf("Result: %t\n\n", result)
	}
}
