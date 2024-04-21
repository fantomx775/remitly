package main

import (
	"fmt"
	"io/ioutil"
	"os"
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
			name: "ResourceFieldMissing",
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
			expectedError:  "Resource field is missing",
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
			expectedError:  "Resource field is not a string or a list",
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
			expectedError:  "Resource field is missing",
		},
		{
			name: "MultipleStatementsWithMultipleResourcesWithOneResourceIsAsterisk",
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
							"Sid":    "IamListAccess2",
							"Effect": "Allow",
							"Action": []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": []interface{}{
								"*",
								"***",
							},
						},
						map[string]interface{}{
							"Sid":      "IamListAccess3",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "smth",
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
			expectedError:  "",
		},
		{
			name: "MultipleStatementsWithMultipleResourcesWithNoneResourceIsAsterisk",
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
							"Sid":    "IamListAccess2",
							"Effect": "Allow",
							"Action": []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": []interface{}{
								"not*",
								"***",
								" * ",
							},
						},
						map[string]interface{}{
							"Sid":      "IamListAccess3",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "smth",
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
			expectedResult: true,
			expectedError:  "",
		},
		{
			name: "MultipleStatementsWithMultipleResourcesWithNoneResourceIsAsterisk",
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
							"Sid":    "IamListAccess2",
							"Effect": "Allow",
							"Action": []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": []interface{}{
								"not*",
								"***",
								" * ",
							},
						},
						map[string]interface{}{
							"Sid":      "IamListAccess3",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "smth",
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
			expectedResult: true,
			expectedError:  "",
		},
		{
			name: "NoVersionField",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Statement": []interface{}{
						map[string]interface{}{
							"Sid":      "IamListAccess1",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "***",
						},
						map[string]interface{}{
							"Sid":    "IamListAccess2",
							"Effect": "Allow",
							"Action": []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": []interface{}{
								"not*",
								"***",
								" * ",
							},
						},
						map[string]interface{}{
							"Sid":      "IamListAccess3",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "smth",
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
			expectedError:  "Version field is missing",
		},
		{
			name: "NoVersionField",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
				},
			},
			expectedResult: false,
			expectedError:  "Statement field is missing",
		},
		{
			name: "NoEffectField",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Sid":      "IamListAccess",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "not*",
						},
					},
				},
			},
			expectedResult: false,
			expectedError:  "Effect field is missing",
		},
		{
			name: "NoActionField",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Effect":   "Allow",
							"Sid":      "IamListAccess",
							"Resource": "not*",
						},
					},
				},
			},
			expectedResult: false,
			expectedError:  "Action field is missing",
		},
		{
			name: "ActionFieldIsNotStringOrList",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Effect":   "Allow",
							"Action":   true,
							"Sid":      "IamListAccess",
							"Resource": "not*",
						},
					},
				},
			},
			expectedResult: false,
			expectedError:  "Action field is not a string or a list",
		},
		{
			name: "ActionFieldIsNotStringOrList",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", 1},
							"Sid":      "IamListAccess",
							"Resource": "not*",
						},
					},
				},
			},
			expectedResult: false,
			expectedError:  "Action field contains non-string value",
		},
		{
			name: "EffectFieldIsNotString",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Effect":   22,
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Sid":      "IamListAccess",
							"Resource": "not*",
						},
					},
				},
			},
			expectedResult: false,
			expectedError:  "Effect field is not a string",
		},
		{
			name: "EffectFieldIsNotDenyOrAllow",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Effect":   "NotAllow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Sid":      "IamListAccess",
							"Resource": "not*",
						},
					},
				},
			},
			expectedResult: false,
			expectedError:  "Effect field is not 'Allow' or 'Deny'",
		},
		{
			name: "PrincipalPresent",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Sid":       "IamListAccess1",
							"Effect":    "Allow",
							"Action":    []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource":  "***",
							"Principal": 1,
						},
					},
				},
			},
			expectedResult: true,
			expectedError:  "Principal field is not allowed",
		},
		{
			name: "VersionFieldIsNot2012-10-17Or2008-10-17",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-19",
					"Statement": []interface{}{
						map[string]interface{}{
							"Sid":      "IamListAccess1",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "***",
						},
					},
				},
			},
			expectedResult: false,
			expectedError:  "Version field is not '2012-10-17' neither '2008-10-17'",
		},
		{
			name: "VersionIsNotString",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": 212,
					"Statement": []interface{}{
						map[string]interface{}{
							"Sid":      "IamListAccess1",
							"Effect":   "Allow",
							"Action":   []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource": "***",
						},
					},
				},
			},
			expectedResult: true,
			expectedError:  "Version field is not a string",
		},
		{
			name: "ForbidenFieldInStatement",
			data: map[string]interface{}{
				"PolicyName": "root",
				"PolicyDocument": map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []interface{}{
						map[string]interface{}{
							"Sid":             "IamListAccess1",
							"Effect":          "Allow",
							"Action":          []interface{}{"iam:ListRoles", "iam:ListUsers"},
							"Resource":        "***",
							"AdditionalField": "smth",
						},
					},
				},
			},
			expectedResult: false,
			expectedError:  "unexpected field AdditionalField",
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
func TestReadJSONsFromFile(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "test.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	validJSON := `{"key": "value"}`
	if _, err := tmpfile.Write([]byte(validJSON)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	invalidJSON := `{"key": "value"`
	if err := os.WriteFile(tmpfile.Name(), []byte(invalidJSON), 0644); err != nil {
		t.Fatal(err)
	}

	_, err = readJSONsFromFile(tmpfile.Name())
	if err == nil {
		t.Errorf("Expected non-nil error for invalid JSON, got nil")
	}
}
