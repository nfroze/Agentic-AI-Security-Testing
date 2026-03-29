# Construct database URL from RDS endpoint
locals {
  database_url = "postgresql://${var.db_username}:${random_password.db_password.result}@${aws_db_instance.main.endpoint}/${var.db_name}"
}

# Store database URL in Secrets Manager
resource "aws_secretsmanager_secret" "db_url" {
  name_prefix             = "${var.project_name}-db-url-"
  recovery_window_in_days = 0
  description             = "Database connection URL for ${var.project_name}"

  tags = {
    Name = "${var.project_name}-db-url"
  }
}

resource "aws_secretsmanager_secret_version" "db_url" {
  secret_id     = aws_secretsmanager_secret.db_url.id
  secret_string = local.database_url
}

# OpenAI API Key (placeholder or actual value)
resource "aws_secretsmanager_secret" "openai_api_key" {
  name_prefix             = "${var.project_name}-openai-key-"
  recovery_window_in_days = 7
  description             = "OpenAI API key for ${var.project_name}"

  tags = {
    Name = "${var.project_name}-openai-key"
  }
}

resource "aws_secretsmanager_secret_version" "openai_api_key" {
  secret_id = aws_secretsmanager_secret.openai_api_key.id
  secret_string = var.openai_api_key != "" ? var.openai_api_key : jsonencode({
    "api_key" = "placeholder-set-via-aws-console-or-variable"
  })
}

# Anthropic API Key (placeholder or actual value)
resource "aws_secretsmanager_secret" "anthropic_api_key" {
  name_prefix             = "${var.project_name}-anthropic-key-"
  recovery_window_in_days = 7
  description             = "Anthropic API key for ${var.project_name}"

  tags = {
    Name = "${var.project_name}-anthropic-key"
  }
}

resource "aws_secretsmanager_secret_version" "anthropic_api_key" {
  secret_id = aws_secretsmanager_secret.anthropic_api_key.id
  secret_string = var.anthropic_api_key != "" ? var.anthropic_api_key : jsonencode({
    "api_key" = "placeholder-set-via-aws-console-or-variable"
  })
}
