variable "aws_region" {
  description = "AWS region for infrastructure deployment"
  type        = string
  default     = "eu-west-2"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-\\d{1}$", var.aws_region))
    error_message = "AWS region must be a valid region format (e.g., eu-west-2)."
  }
}

variable "environment" {
  description = "Environment name (production, staging, development)"
  type        = string
  default     = "production"

  validation {
    condition     = contains(["production", "staging", "development"], var.environment)
    error_message = "Environment must be one of: production, staging, development."
  }
}

variable "project_name" {
  description = "Project name for resource naming and tagging"
  type        = string
  default     = "agentic-security"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid CIDR block."
  }
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (should span 2 AZs)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]

  validation {
    condition     = length(var.public_subnet_cidrs) == 2
    error_message = "Must provide exactly 2 public subnet CIDR blocks for high availability."
  }
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (should span 2 AZs)"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.11.0/24"]

  validation {
    condition     = length(var.private_subnet_cidrs) == 2
    error_message = "Must provide exactly 2 private subnet CIDR blocks for high availability."
  }
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.micro"
}

variable "db_name" {
  description = "Name of the initial database"
  type        = string
  default     = "agentic_security"

  validation {
    condition     = can(regex("^[a-z0-9_]+$", var.db_name))
    error_message = "Database name must contain only lowercase letters, numbers, and underscores."
  }
}

variable "db_username" {
  description = "Master username for RDS"
  type        = string
  default     = "agentic_admin"

  validation {
    condition     = can(regex("^[a-z][a-z0-9_]*$", var.db_username)) && length(var.db_username) <= 16
    error_message = "Database username must start with a letter, contain only lowercase letters/numbers/underscores, and be max 16 characters."
  }
}

variable "api_container_port" {
  description = "Port the API container listens on"
  type        = number
  default     = 8000

  validation {
    condition     = var.api_container_port > 1024 && var.api_container_port < 65535
    error_message = "Container port must be between 1024 and 65535."
  }
}

variable "dashboard_container_port" {
  description = "Port the dashboard container listens on"
  type        = number
  default     = 8080

  validation {
    condition     = var.dashboard_container_port > 1024 && var.dashboard_container_port < 65535
    error_message = "Container port must be between 1024 and 65535."
  }
}

variable "api_cpu" {
  description = "CPU units for API task (256, 512, 1024, 2048, 4096)"
  type        = number
  default     = 512

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096], var.api_cpu)
    error_message = "API CPU must be one of: 256, 512, 1024, 2048, 4096."
  }
}

variable "api_memory" {
  description = "Memory (MB) for API task (512-30720, must be valid for CPU)"
  type        = number
  default     = 1024

  validation {
    condition     = var.api_memory >= 512 && var.api_memory <= 30720
    error_message = "API memory must be between 512 and 30720 MB."
  }
}

variable "dashboard_cpu" {
  description = "CPU units for dashboard task (256, 512, 1024, 2048, 4096)"
  type        = number
  default     = 256

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096], var.dashboard_cpu)
    error_message = "Dashboard CPU must be one of: 256, 512, 1024, 2048, 4096."
  }
}

variable "dashboard_memory" {
  description = "Memory (MB) for dashboard task (512-30720, must be valid for CPU)"
  type        = number
  default     = 512

  validation {
    condition     = var.dashboard_memory >= 512 && var.dashboard_memory <= 30720
    error_message = "Dashboard memory must be between 512 and 30720 MB."
  }
}

variable "desired_count" {
  description = "Number of ECS tasks to run (set to 0 to disable service)"
  type        = number
  default     = 1

  validation {
    condition     = var.desired_count >= 0 && var.desired_count <= 10
    error_message = "Desired count must be between 0 and 10."
  }
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection for ALB (disable for easy teardown)"
  type        = bool
  default     = false
}

variable "alb_certificate_arn" {
  description = "ARN of SSL/TLS certificate for HTTPS (optional)"
  type        = string
  default     = ""
}

variable "openai_api_key" {
  description = "OpenAI API key for testing (optional, stored in Secrets Manager)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "anthropic_api_key" {
  description = "Anthropic API key for testing (optional, stored in Secrets Manager)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention must be a valid CloudWatch retention period."
  }
}

variable "rds_storage_size" {
  description = "Initial RDS storage size in GB"
  type        = number
  default     = 20

  validation {
    condition     = var.rds_storage_size >= 20 && var.rds_storage_size <= 65536
    error_message = "RDS storage size must be between 20 and 65536 GB."
  }
}

variable "enable_rds_encryption" {
  description = "Enable encryption at rest for RDS"
  type        = bool
  default     = true
}

variable "enable_alb_logging" {
  description = "Enable access logging for ALB to S3"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
