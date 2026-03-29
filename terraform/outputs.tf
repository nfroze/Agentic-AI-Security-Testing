output "alb_dns_name" {
  description = "DNS name of the load balancer"
  value       = aws_lb.main.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the load balancer (for Route53)"
  value       = aws_lb.main.zone_id
}

output "api_endpoint" {
  description = "API endpoint URL"
  value       = "http://${aws_lb.main.dns_name}/api"
}

output "dashboard_endpoint" {
  description = "Dashboard endpoint URL"
  value       = "http://${aws_lb.main.dns_name}"
}

output "api_url_https" {
  description = "HTTPS API endpoint (if certificate provided)"
  value       = var.alb_certificate_arn != "" ? "https://${aws_lb.main.dns_name}/api" : "N/A"
}

output "dashboard_url_https" {
  description = "HTTPS dashboard endpoint (if certificate provided)"
  value       = var.alb_certificate_arn != "" ? "https://${aws_lb.main.dns_name}" : "N/A"
}

output "ecr_api_repository_url" {
  description = "URL of the API ECR repository"
  value       = aws_ecr_repository.api.repository_url
}

output "ecr_dashboard_repository_url" {
  description = "URL of the dashboard ECR repository"
  value       = aws_ecr_repository.dashboard.repository_url
}

output "rds_endpoint" {
  description = "RDS database endpoint"
  value       = aws_db_instance.main.endpoint
  sensitive   = true
}

output "rds_hostname" {
  description = "RDS database hostname only"
  value       = aws_db_instance.main.address
  sensitive   = true
}

output "rds_port" {
  description = "RDS database port"
  value       = aws_db_instance.main.port
}

output "rds_database_name" {
  description = "RDS database name"
  value       = aws_db_instance.main.db_name
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "private_subnet_ids" {
  description = "IDs of private subnets"
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = aws_subnet.public[*].id
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.main.name
}

output "ecs_cluster_arn" {
  description = "ARN of the ECS cluster"
  value       = aws_ecs_cluster.main.arn
}

output "s3_reports_bucket_name" {
  description = "Name of the S3 bucket for storing reports"
  value       = aws_s3_bucket.reports.id
}

output "s3_reports_bucket_arn" {
  description = "ARN of the S3 bucket for storing reports"
  value       = aws_s3_bucket.reports.arn
}

output "cloudwatch_log_group_api" {
  description = "CloudWatch log group for API"
  value       = aws_cloudwatch_log_group.ecs_api.name
}

output "cloudwatch_log_group_dashboard" {
  description = "CloudWatch log group for dashboard"
  value       = aws_cloudwatch_log_group.ecs_dashboard.name
}

output "cloudwatch_log_group_vpc_flow_logs" {
  description = "CloudWatch log group for VPC Flow Logs"
  value       = aws_cloudwatch_log_group.vpc_flow_logs.name
}

output "sns_topic_alarms_arn" {
  description = "ARN of the SNS topic for alarms"
  value       = aws_sns_topic.alarms.arn
}

output "secrets_manager_db_password_name" {
  description = "Name of the Secrets Manager secret for DB password"
  value       = aws_secretsmanager_secret.db_password.name
  sensitive   = true
}

output "secrets_manager_db_url_name" {
  description = "Name of the Secrets Manager secret for DB URL"
  value       = aws_secretsmanager_secret.db_url.name
  sensitive   = true
}

output "ecs_task_execution_role_arn" {
  description = "ARN of the ECS task execution role"
  value       = aws_iam_role.ecs_task_execution_role.arn
}

output "ecs_task_role_arn" {
  description = "ARN of the ECS task role"
  value       = aws_iam_role.ecs_task_role.arn
}

output "alb_security_group_id" {
  description = "Security group ID of the ALB"
  value       = aws_security_group.alb.id
}

output "ecs_security_group_id" {
  description = "Security group ID of ECS tasks"
  value       = aws_security_group.ecs.id
}

output "rds_security_group_id" {
  description = "Security group ID of RDS database"
  value       = aws_security_group.rds.id
}
