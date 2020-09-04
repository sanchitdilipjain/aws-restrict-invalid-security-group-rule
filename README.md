# aws-restrict-security-group


- This stack deploys an AWS Lambda which triggers whenever a security group ingress rule is added, and removes the rule if the IP allowed is ‘0.0.0.0/0’ or ‘::/0’, replacing them with the specified IP ranges

- Prerequisite: The email app password needs to be stored in Secrets Manager. Default CloudTrail needs to be enabled for the region in which the stack is deployed,   so that the CloudWatch event will work. (One CloudTrail is free for every AWS Account). ARN of an IAM role with proper permissions which will be assumed by the     Lambda is required.

- Regional stack : Needs to be deployed in each region separately

- The function has provisions for both rule specific exceptions and security group id specific exceptions
