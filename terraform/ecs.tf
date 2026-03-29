# ECS Cluster with Container Insights enabled
resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "${var.project_name}-cluster"
  }
}

# CloudWatch log group for ECS tasks
resource "aws_cloudwatch_log_group" "ecs_api" {
  name              = "/ecs/${var.project_name}-api"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-ecs-api-logs"
  }
}

resource "aws_cloudwatch_log_group" "ecs_dashboard" {
  name              = "/ecs/${var.project_name}-dashboard"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-ecs-dashboard-logs"
  }
}

# IAM Role for ECS Task Execution (pulls images, writes logs, reads secrets)
resource "aws_iam_role" "ecs_task_execution_role" {
  name_prefix = "ecs-task-execution-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-ecs-task-execution-role"
  }
}

# Attach managed policy for ECS task execution
resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Policy for ECS task execution to read from ECR and Secrets Manager
resource "aws_iam_role_policy" "ecs_task_execution_ecr_secrets" {
  name_prefix = "ecs-task-execution-ecr-secrets-"
  role        = aws_iam_role.ecs_task_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.db_password.arn,
          aws_secretsmanager_secret.db_url.arn,
          aws_secretsmanager_secret.openai_api_key.arn,
          aws_secretsmanager_secret.anthropic_api_key.arn
        ]
      }
    ]
  })
}

# IAM Role for ECS Task (permissions for application)
resource "aws_iam_role" "ecs_task_role" {
  name_prefix = "ecs-task-role-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-ecs-task-role"
  }
}

# Policy for ECS task to access S3 reports bucket
resource "aws_iam_role_policy" "ecs_task_s3" {
  name_prefix = "ecs-task-s3-"
  role        = aws_iam_role.ecs_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.reports.arn,
          "${aws_s3_bucket.reports.arn}/*"
        ]
      }
    ]
  })
}

# Policy for ECS task to read API keys from Secrets Manager
resource "aws_iam_role_policy" "ecs_task_secrets" {
  name_prefix = "ecs-task-secrets-"
  role        = aws_iam_role.ecs_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.openai_api_key.arn,
          aws_secretsmanager_secret.anthropic_api_key.arn
        ]
      }
    ]
  })
}

# ===== API Task Definition =====

resource "aws_ecs_task_definition" "api" {
  family                   = "${var.project_name}-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.api_cpu
  memory                   = var.api_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "${var.project_name}-api"
      image     = "${aws_ecr_repository.api.repository_url}:latest"
      essential = true
      portMappings = [
        {
          containerPort = var.api_container_port
          hostPort      = var.api_container_port
          protocol      = "tcp"
        }
      ]

      # Environment variables (non-sensitive)
      environment = [
        {
          name  = "LOG_LEVEL"
          value = var.environment == "production" ? "INFO" : "DEBUG"
        },
        {
          name  = "PYTHONUNBUFFERED"
          value = "1"
        },
        {
          name  = "AWS_REGION"
          value = var.aws_region
        }
      ]

      # Secrets (sensitive, loaded from Secrets Manager)
      secrets = [
        {
          name      = "DATABASE_URL"
          valueFrom = aws_secretsmanager_secret.db_url.arn
        },
        {
          name      = "OPENAI_API_KEY"
          valueFrom = aws_secretsmanager_secret.openai_api_key.arn
        },
        {
          name      = "ANTHROPIC_API_KEY"
          valueFrom = aws_secretsmanager_secret.anthropic_api_key.arn
        }
      ]

      # Logging configuration
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_api.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }

      # Health check
      healthCheck = {
        command     = ["CMD-SHELL", "python -c 'import urllib.request; urllib.request.urlopen(\"http://localhost:${var.api_container_port}/health\")' || exit 1"]
        interval    = 30
        timeout     = 10
        retries     = 3
        startPeriod = 60
      }

      # Security hardening
      readonlyRootFilesystem = true
      mountPoints = [
        {
          sourceVolume  = "tmp"
          containerPath = "/tmp"
          readOnly      = false
        }
      ]

      linuxParameters = {
        capabilities = {
          drop = ["ALL"]
          add  = ["NET_BIND_SERVICE"]
        }
      }
    }
  ])

  # tmpfs mount for /tmp (read-write, noexec)
  volume {
    name = "tmp"
    ephemeralStorage = {
      sizeInGiB = 10
    }
  }

  tags = {
    Name = "${var.project_name}-api-task"
  }
}

# ===== Dashboard Task Definition =====

resource "aws_ecs_task_definition" "dashboard" {
  family                   = "${var.project_name}-dashboard"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.dashboard_cpu
  memory                   = var.dashboard_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "${var.project_name}-dashboard"
      image     = "${aws_ecr_repository.dashboard.repository_url}:latest"
      essential = true
      portMappings = [
        {
          containerPort = var.dashboard_container_port
          hostPort      = var.dashboard_container_port
          protocol      = "tcp"
        }
      ]

      # Logging configuration
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_dashboard.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }

      # Health check
      healthCheck = {
        command     = ["CMD-SHELL", "wget --quiet --tries=1 --spider http://localhost:${var.dashboard_container_port}/ || exit 1"]
        interval    = 30
        timeout     = 10
        retries     = 3
        startPeriod = 30
      }

      # Security hardening
      readonlyRootFilesystem = true
      mountPoints = [
        {
          sourceVolume  = "cache"
          containerPath = "/var/cache/nginx"
          readOnly      = false
        },
        {
          sourceVolume  = "run"
          containerPath = "/var/run/nginx"
          readOnly      = false
        }
      ]

      linuxParameters = {
        capabilities = {
          drop = ["ALL"]
          add  = ["NET_BIND_SERVICE"]
        }
      }
    }
  ])

  # Ephemeral storage for nginx cache and runtime
  volume {
    name = "cache"
    ephemeralStorage = {
      sizeInGiB = 5
    }
  }

  volume {
    name = "run"
    ephemeralStorage = {
      sizeInGiB = 2
    }
  }

  tags = {
    Name = "${var.project_name}-dashboard-task"
  }
}

# ===== ECS Services =====

# API Service
resource "aws_ecs_service" "api" {
  name            = "${var.project_name}-api-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "${var.project_name}-api"
    container_port   = var.api_container_port
  }

  deployment_configuration {
    maximum_percent         = 200
    minimum_healthy_percent = 50
    deployment_circuit_breaker {
      enable   = true
      rollback = true
    }
  }

  depends_on = [
    aws_lb_listener.http,
    aws_iam_role_policy.ecs_task_execution_ecr_secrets
  ]

  tags = {
    Name = "${var.project_name}-api-service"
  }

  lifecycle {
    ignore_changes = [desired_count]
  }
}

# Dashboard Service
resource "aws_ecs_service" "dashboard" {
  name            = "${var.project_name}-dashboard-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.dashboard.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.dashboard.arn
    container_name   = "${var.project_name}-dashboard"
    container_port   = var.dashboard_container_port
  }

  deployment_configuration {
    maximum_percent         = 200
    minimum_healthy_percent = 50
    deployment_circuit_breaker {
      enable   = true
      rollback = true
    }
  }

  depends_on = [
    aws_lb_listener.http,
    aws_iam_role_policy.ecs_task_execution_ecr_secrets
  ]

  tags = {
    Name = "${var.project_name}-dashboard-service"
  }

  lifecycle {
    ignore_changes = [desired_count]
  }
}
