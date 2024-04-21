package main

import (
	"fmt"
	"testing"
)

func TestVerifyIAMRolePolicy(t *testing.T) {
	testCases := []struct {
		name           string
		data           map[string]interface{}
		expectedResult bool
		expectedError  string
	}{
		{
			name: "PolicyDocumentNotDictionary",
			data: map[string]interface{}{
				"PolicyDocument": "Not a dictionary",
			},
			expectedResult: false,
			expectedError:  "PolicyDocument is not a dictionary",
		},
		{
			name: "StatementNotList",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version":   "2012-10-17",
					"Statement": "Not a list",
				},
			},
			expectedResult: false,
			expectedError:  "Statement field is not a list",
		},
		{
			name: "StatementEmpty",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version":   "2012-10-17",
					"Statement": []interface{}{},
				},
			},
			expectedResult: false,
			expectedError:  "Statement field is empty",
		},
		{
			name: "StatementNotDictionary",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version":   "2012-10-17",
					"Statement": []interface{}{"Not a dictionary"},
				},
			},
			expectedResult: false,
			expectedError:  "Statement is not a dictionary",
		},
		{
			name: "ResourceFieldMissingOrNotString",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Sid":    "IamListAccess",
							"Effect": "Allow",
							"Action": []interface{}{"iam:ListRoles", "iam:ListUsers"},
						},
					},
				},
			},
			expectedResult: false,
			expectedError:  "Resource field is missing or not a string",
		},
		{
			name: "ResourceIsAsterisk",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Sid":      "IamListAccess",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "*",
						},
					},
				},
			},
			expectedResult: false,
			expectedError:  "",
		},
		{
			name: "ResourceIsNotAsterisk",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Sid":      "IamListAccess",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "not*",
						},
					},
				},
			},
			expectedResult: true,
			expectedError:  "",
		},
		{
			name: "MultipleStatementsWithOneResourceIsAsterisk",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Sid":      "IamListAccess1",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "$",
						},
						map[string]interface{}{
							"Sid":      "IamListAccess2",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "*",
						},
						map[string]interface{}{
							"Sid":      "IamListAccess3",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "#",
						},
					},
				},
			},
			expectedResult: false,
			expectedError:  "",
		},
		{
			name: "MultipleStatementsWithAtLeastOneResourceIsAsterisk",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Sid":      "IamListAccess1",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "*",
						},
						map[string]interface{}{
							"Sid":      "IamListAccess2",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "*",
						},
						map[string]interface{}{
							"Sid":      "IamListAccess3",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "**",
						},
					},
				},
			},
			expectedResult: false,
			expectedError:  "",
		},
		{
			name: "MultipleStatementsWithNoneResourceIsAsterisk",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Sid":      "IamListAccess1",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "***",
						},
						map[string]interface{}{
							"Sid":      "IamListAccess2",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "not*",
						},
						map[string]interface{}{
							"Sid":      "IamListAccess3",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "*not",
						},
					},
				},
			},
			expectedResult: true,
			expectedError:  "",
		},
		{
			name: "MultipleStatementsWithInvalidResource",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Sid":      "IamListAccess1",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "***",
						},
						map[string]interface{}{
							"Sid":      "IamListAccess2",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": true,
						},
						map[string]interface{}{
							"Sid":      "IamListAccess3",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "*not",
						},
					},
				},
			},
			expectedResult: false,
			expectedError:  "Resource field is missing or not a string",
		},
		{
			name: "MultipleStatementsWithNoResource",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Sid":      "IamListAccess1",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "***",
						},
						map[string]interface{}{
							"Sid":      "IamListAccess2",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "*",
						},
						map[string]interface{}{
							"Sid":    "IamListAccess3",
							"Effect": "Allow",
							"Action": []interface{}{"iam:ListRoles", "iam:ListUsers"},
						},
						map[string]interface{}{
							"Sid":      "IamListAccess4",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "*not",
						},
					},
				},
			},
			expectedResult: false,
			expectedError:  "Resource field is missing or not a string",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := verifyIAMRolePolicy(tc.data)
			fmt.Println(res, err)
			if err != nil {
				if tc.expectedError != err.Error() {
					t.Errorf("Expected error '%s', but got %v", tc.expectedError, err)
				}
			} else {
				if tc.expectedResult != res {
					t.Errorf("Expected result '%t', but got %t", tc.expectedResult, res)
				}
			}
		})
	}

}
