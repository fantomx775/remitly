package main

import (
	"testing"
)

func TestVerifyIAMRolePolicy(t *testing.T) {
	// Test case 1
	data := map[string]interface{}{
		"PolicyDocument": "Not a dictionary",
	}

	_, err := verifyIAMRolePolicy(data)
	if err.Error() != "PolicyDocument is not a dictionary" {
		t.Errorf("Expected error 'PolicyDocument is not a dictionary', but got %v", err)
	}

	// Test case 2
	data = map[string]interface{}{
		"PolicyName":     "root",
		"PolicyDocument": map[string]interface{}{"Version": "2012-10-17", "Statement": "Not a list"},
	}

	_, err = verifyIAMRolePolicy(data)
	if err.Error() != "Statement field is not a list" {
		t.Errorf("Expected error 'Statement field is not a list', but got %v", err)
	}

	// Test case 3
	data = map[string]interface{}{
		"PolicyName":     "root",
		"PolicyDocument": map[string]interface{}{"Version": "2012-10-17", "Statement": []interface{}{}},
	}

	_, err = verifyIAMRolePolicy(data)
	if err.Error() != "Statement field is empty" {
		t.Errorf("Expected error 'Statement field is empty', but got %v", err)
	}

	// Test case 4
	data = map[string]interface{}{
		"PolicyName":     "root",
		"PolicyDocument": map[string]interface{}{"Version": "2012-10-17", "Statement": []interface{}{"Not a dictionary"}},
	}

	_, err = verifyIAMRolePolicy(data)
	if err.Error() != "Statement is not a dictionary" {
		t.Errorf("Expected error 'Statement field is not a dictionary', but got %v", err)
	}

	// Test case 5
	data = map[string]interface{}{
		"PolicyName": "root",
		"PolicyDocument": map[string]interface{}{
			"Version":   "2012-10-17",
			"Statement": []interface{}{map[string]interface{}{"Sid": "IamListAccess", "Effect": "Allow", "Action": []interface{}{"iam:ListRoles", "iam:ListUsers"}}},
		},
	}

	_, err = verifyIAMRolePolicy(data)
	if err.Error() != "Resource field is missing or not a string" {
		t.Errorf("Expected error 'Resource field is missing or not a string', but got %v", err)
	}

	// Test case 6
	data = map[string]interface{}{
		"PolicyName": "root",
		"PolicyDocument": map[string]interface{}{
			"Version":   "2012-10-17",
			"Statement": []interface{}{map[string]interface{}{"Sid": "IamListAccess", "Effect": "Allow", "Action": []interface{}{"iam:ListRoles", "iam:ListUsers"},  "Resource": "*"}},
		},
	}

	res, err := verifyIAMRolePolicy(data)
	if res != false && err != nil {
		t.Errorf("Expected result: false, got: true")
	}

	// Test case 7
	data = map[string]interface{}{
		"PolicyName": "root",
		"PolicyDocument": map[string]interface{}{
			"Version":   "2012-10-17",
			"Statement": []interface{}{map[string]interface{}{"Sid": "IamListAccess", "Effect": "Allow", "Action": []interface{}{"iam:ListRoles", "iam:ListUsers"},  "Resource": "not*"}},
		},
	}

	res, _ = verifyIAMRolePolicy(data)
	if res != true {
		t.Errorf("Expected result: true, got: false")
	}

	
}
