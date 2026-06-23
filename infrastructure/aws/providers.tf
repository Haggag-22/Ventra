provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Purpose     = "ventra-collector-lab"
    }
  }
}

# CloudFront + WAF must be in us-east-1 for CLOUDFRONT scope
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Purpose     = "ventra-collector-lab"
    }
  }
}
