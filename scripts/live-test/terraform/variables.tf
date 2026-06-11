variable "region" {
  description = "Region to deploy the test environment into."
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type (free-tier eligible by default)."
  type        = string
  default     = "t3.micro"
}

variable "create_ec2" {
  description = "Create the EC2 instance, EBS volume, and snapshot. Set false to skip the only hourly-billed compute."
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Stand up an AWS Config recorder + delivery channel. Off by default (adds per-item cost and an S3 bucket)."
  type        = bool
  default     = false
}

variable "make_bucket_public" {
  description = "Attach an anonymous public-read bucket policy (a real exposure). Leave false; let Stratus produce public exposures instead."
  type        = bool
  default     = false
}

variable "make_lambda_public" {
  description = "Attach a wildcard-principal invoke permission to the Lambda (tests cross-account-invoke detection)."
  type        = bool
  default     = false
}
