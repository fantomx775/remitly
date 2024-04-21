# Verifying AWS::IAM::Role Policy

A program written in Go, that verifies AWS::IAM::Role Policy.
The method of the program that does the verifying is `verifyIAMRolePolicy`

### Task
Method should return logical false if an input JSON `Resource` field contains a single asterisk and true in any other case. 
### Problems
1. AWS::IAM::Role Policy `Resource` field may be a list.
2. Statement may contain couple of `Resource` fields.

### Example of such a AWS::IAM::Role Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FirstStatement",
      "Effect": "Allow",
      "Action": ["iam:ChangePassword"],
      "Resource": "*"
    },
    {
      "Sid": "SecondStatement",
      "Effect": "Allow",
      "Action": "s3:ListAllMyBuckets",
      "Resource": "*"
    },
    {
      "Sid": "ThirdStatement",
      "Effect": "Allow",
      "Action": [
        "s3:List*",
        "s3:Get*"
      ],
      "Resource": [
        "arn:aws:s3:::confidential-data",
        "arn:aws:s3:::confidential-data/*"
      ],
      "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    }
  ]
}
```
It is not stated in the task description how to handle such policies. So I implemented the method as follows:
1. If `Resource` field is a list and contains at least one single asterisk method will return false.
2. If there are multiple `Resource` fields and any of them contains one single asterisk method will return false.
   
## Usage

To use program make sure to have Go installed.
Then to verify AWS::IAM::Role Policy, pass path to JSON file containing this policy like so:

```bash
go run verify_iam.go <path_to_json_file>
```

## Tests

Test files contains multiple various tests, to run them I recommend using IDE such as IntelliJ for nice visualization.
You can also run them directly from terminal using:

```bash
go test
```

The last lines should look like this:

```bash
PASS
ok      test3   0.019s
```

indicating that tests were succesful and time they took.
(`test3` is only name of the package)
