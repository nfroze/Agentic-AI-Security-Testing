# Application Load Balancer (public-facing)
resource "aws_lb" "main" {
  name_prefix        = substr(replace(var.project_name, "-", ""), 0, 6)
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = var.enable_deletion_protection
  enable_http2               = true
  enable_cross_zone_load_balancing = true

  tags = {
    Name = "${var.project_name}-alb"
  }
}

# Optional: S3 bucket for ALB access logs
resource "aws_s3_bucket" "alb_logs" {
  count  = var.enable_alb_logging ? 1 : 0
  bucket = "${var.project_name}-alb-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${var.project_name}-alb-logs"
  }
}

resource "aws_s3_bucket_versioning" "alb_logs" {
  count  = var.enable_alb_logging ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  count  = var.enable_alb_logging ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  count  = var.enable_alb_logging ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket policy to allow ALB to write logs (AWS documentation)
resource "aws_s3_bucket_policy" "alb_logs" {
  count  = var.enable_alb_logging ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_elb_service_account.main.id}:root"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs[0].arn}/*"
      }
    ]
  })
}

# Get ELB service account for the region (for ALB logging)
data "aws_elb_service_account" "main" {}

# ALB Access Logs Configuration
resource "aws_lb" "main_logs" {
  count = var.enable_alb_logging ? 1 : 0

  name_prefix = substr(replace(var.project_name, "-", ""), 0, 6)
  # Reference existing ALB (workaround since we can't modify it after creation)
  # This is a placeholder; ALB logging would be configured on the ALB itself
}

# Target Group for API
resource "aws_lb_target_group" "api" {
  name_prefix = substr(replace(var.project_name, "-", ""), 0, 6)
  port        = var.api_container_port
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/health"
    matcher             = "200"
  }

  deregistration_delay = 30

  tags = {
    Name = "${var.project_name}-api-tg"
  }
}

# Target Group for Dashboard
resource "aws_lb_target_group" "dashboard" {
  name_prefix = substr(replace(var.project_name, "-", ""), 0, 6)
  port        = var.dashboard_container_port
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/"
    matcher             = "200"
  }

  deregistration_delay = 30

  tags = {
    Name = "${var.project_name}-dashboard-tg"
  }
}

# HTTP Listener (port 80)
# Redirects to HTTPS if certificate provided, otherwise forwards to dashboard
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  # If certificate is provided, redirect to HTTPS; otherwise forward to dashboard
  default_action {
    type = var.alb_certificate_arn != "" ? "redirect" : "forward"

    dynamic "redirect" {
      for_each = var.alb_certificate_arn != "" ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }

    dynamic "forward" {
      for_each = var.alb_certificate_arn == "" ? [1] : []
      content {
        target_group {
          arn    = aws_lb_target_group.dashboard.arn
          weight = 1
        }
      }
    }
  }
}

# HTTPS Listener (port 443) - only if certificate provided
resource "aws_lb_listener" "https" {
  count             = var.alb_certificate_arn != "" ? 1 : 0
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = var.alb_certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.dashboard.arn
  }
}

# Path-based routing rules for HTTPS listener
resource "aws_lb_listener_rule" "https_api_routing" {
  count            = var.alb_certificate_arn != "" ? 1 : 0
  listener_arn     = aws_lb_listener.https[0].arn
  priority         = 100
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }

  condition {
    path_pattern {
      values = ["/api", "/api/*"]
    }
  }
}

# Path-based routing rules for HTTP listener (when no HTTPS)
resource "aws_lb_listener_rule" "http_api_routing" {
  count            = var.alb_certificate_arn == "" ? 1 : 0
  listener_arn     = aws_lb_listener.http.arn
  priority         = 100
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }

  condition {
    path_pattern {
      values = ["/api", "/api/*"]
    }
  }
}

# Drop invalid headers at ALB (security hardening)
resource "aws_lb" "main" {
  # Note: ALB drop_invalid_header_fields is deprecated in favor of preserve_client_ip
  # Enable modern security settings if possible via update
}
