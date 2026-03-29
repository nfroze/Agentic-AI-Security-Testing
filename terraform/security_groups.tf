# Security Group for Application Load Balancer
resource "aws_security_group" "alb" {
  name_prefix = "${var.project_name}-alb-"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-alb-sg"
  }
}

# ALB Ingress: HTTP from anywhere
resource "aws_security_group_rule" "alb_http" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.alb.id
  description       = "Allow HTTP from anywhere"
}

# ALB Ingress: HTTPS from anywhere (optional, only if certificate provided)
resource "aws_security_group_rule" "alb_https" {
  count             = var.alb_certificate_arn != "" ? 1 : 0
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.alb.id
  description       = "Allow HTTPS from anywhere"
}

# ALB Egress: To ECS tasks on container ports
resource "aws_security_group_rule" "alb_to_ecs_api" {
  type                     = "egress"
  from_port                = var.api_container_port
  to_port                  = var.api_container_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = aws_security_group.alb.id
  description              = "Allow egress to ECS API tasks"
}

resource "aws_security_group_rule" "alb_to_ecs_dashboard" {
  type                     = "egress"
  from_port                = var.dashboard_container_port
  to_port                  = var.dashboard_container_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = aws_security_group.alb.id
  description              = "Allow egress to ECS dashboard tasks"
}

# Security Group for ECS tasks
resource "aws_security_group" "ecs" {
  name_prefix = "${var.project_name}-ecs-"
  description = "Security group for ECS tasks"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-ecs-sg"
  }
}

# ECS Ingress: From ALB on container ports
resource "aws_security_group_rule" "ecs_from_alb_api" {
  type                     = "ingress"
  from_port                = var.api_container_port
  to_port                  = var.api_container_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb.id
  security_group_id        = aws_security_group.ecs.id
  description              = "Allow inbound from ALB to API"
}

resource "aws_security_group_rule" "ecs_from_alb_dashboard" {
  type                     = "ingress"
  from_port                = var.dashboard_container_port
  to_port                  = var.dashboard_container_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb.id
  security_group_id        = aws_security_group.ecs.id
  description              = "Allow inbound from ALB to dashboard"
}

# ECS Egress: To internet for LLM API calls and package updates
resource "aws_security_group_rule" "ecs_to_internet" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.ecs.id
  description       = "Allow HTTPS egress to LLM providers and package repositories"
}

# ECS Egress: To RDS database
resource "aws_security_group_rule" "ecs_to_rds" {
  type                     = "egress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.rds.id
  security_group_id        = aws_security_group.ecs.id
  description              = "Allow egress to RDS PostgreSQL"
}

# Security Group for RDS
resource "aws_security_group" "rds" {
  name_prefix = "${var.project_name}-rds-"
  description = "Security group for RDS database"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-rds-sg"
  }
}

# RDS Ingress: From ECS tasks only
resource "aws_security_group_rule" "rds_from_ecs" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = aws_security_group.rds.id
  description              = "Allow PostgreSQL inbound from ECS tasks only"
}

# RDS Egress: Deny all outbound (database only accepts, doesn't initiate)
resource "aws_security_group_rule" "rds_egress_deny" {
  type              = "egress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  cidr_blocks       = ["127.0.0.1/32"]
  security_group_id = aws_security_group.rds.id
  description       = "Deny all outbound traffic (database shouldn't initiate)"
}
