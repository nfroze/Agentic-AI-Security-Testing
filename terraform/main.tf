terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  # Local backend for state management
  # For production, migrate to S3 backend with:
  #   backend "s3" {
  #     bucket         = "agentic-security-tfstate"
  #     key            = "infrastructure/terraform.tfstate"
  #     region         = "eu-west-2"
  #     encrypt        = true
  #     dynamodb_table = "terraform-locks"
  #   }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "agentic-ai-security-testing"
      ManagedBy   = "terraform"
      Environment = var.environment
      Owner       = "noah-frost"
      Repository  = "agentic-ai-security-testing"
    }
  }
}

# Data source for current AWS account ID
data "aws_caller_identity" "current" {}

# Data source for availability zones in the region
data "aws_availability_zones" "available" {
  state = "available"
}
