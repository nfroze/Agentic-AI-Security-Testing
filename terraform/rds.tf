# RDS PostgreSQL Database Instance
resource "aws_db_instance" "main" {
  identifier              = "${var.project_name}-db"
  engine                  = "postgres"
  engine_version          = "15"
  instance_class          = var.db_instance_class
  allocated_storage       = var.rds_storage_size
  storage_type            = "gp3"
  storage_encrypted       = var.enable_rds_encryption
  multi_az                = false # Cost optimization; set to true for HA
  publicly_accessible     = false

  db_name                = var.db_name
  username               = var.db_username
  password               = random_password.db_password.result
  parameter_group_name   = aws_db_parameter_group.main.name
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  # Backup configuration
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"
  copy_tags_to_snapshot   = true

  # Deletion protection
  deletion_protection = var.enable_deletion_protection
  skip_final_snapshot = !var.enable_deletion_protection
  final_snapshot_identifier = var.enable_deletion_protection ? "${var.project_name}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}" : null

  # Monitoring
  enabled_cloudwatch_logs_exports = ["postgresql"]
  monitoring_interval             = 0 # Disable enhanced monitoring to reduce costs
  performance_insights_enabled     = false

  # Security
  iam_database_authentication_enabled = false # Optional, requires additional setup
  auto_minor_version_upgrade         = true

  tags = {
    Name = "${var.project_name}-db"
  }

  depends_on = [aws_db_subnet_group.main]

  lifecycle {
    # Prevent accidental deletion of production database
    prevent_destroy = false
  }
}

# RDS Parameter Group (enforces SSL, security settings)
resource "aws_db_parameter_group" "main" {
  name_prefix = "${var.project_name}-db-params-"
  family      = "postgres15"
  description = "Custom parameter group for ${var.project_name}"

  # Enforce SSL connections
  parameter {
    name  = "rds.force_ssl"
    value = "1"
    apply_method = "pending-reboot"
  }

  # Security: Log connections
  parameter {
    name  = "log_connections"
    value = "1"
    apply_method = "immediate"
  }

  # Security: Log disconnections
  parameter {
    name  = "log_disconnections"
    value = "1"
    apply_method = "immediate"
  }

  # Logging: Log statement duration for slow queries
  parameter {
    name  = "log_min_duration_statement"
    value = "5000" # Log queries slower than 5 seconds
    apply_method = "immediate"
  }

  tags = {
    Name = "${var.project_name}-db-parameter-group"
  }
}

# Random password for database user
resource "random_password" "db_password" {
  length  = 24
  special = true
  override_special = "!#$%&*()-_=+[]{}<>:?"

  keepers = {
    username = var.db_username
  }
}

# Store DB password in Secrets Manager
resource "aws_secretsmanager_secret" "db_password" {
  name_prefix             = "${var.project_name}-db-password-"
  recovery_window_in_days = 0 # Immediate deletion (use 7+ for production)
  description             = "RDS master password for ${var.project_name}"

  tags = {
    Name = "${var.project_name}-db-password"
  }
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db_password.result
}

# CloudWatch Log Group for RDS PostgreSQL logs
resource "aws_cloudwatch_log_group" "rds_logs" {
  name              = "/aws/rds/instance/${var.project_name}-db/postgresql"
  retention_in_days = 14

  tags = {
    Name = "${var.project_name}-rds-logs"
  }
}
