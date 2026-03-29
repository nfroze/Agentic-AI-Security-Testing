# ECR Repository for API container
resource "aws_ecr_repository" "api" {
  name                 = "${var.project_name}-api"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Name = "${var.project_name}-api-repo"
  }
}

# Lifecycle policy to keep last 5 images, expire untagged after 7 days
resource "aws_ecr_lifecycle_policy" "api" {
  repository = aws_ecr_repository.api.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 5 images, expire untagged images after 7 days"
        selection = {
          tagStatus     = "untagged"
          countType     = "sinceImagePushed"
          countUnit     = "days"
          countNumber   = 7
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Keep last 5 tagged images"
        selection = {
          tagStatus       = "tagged"
          tagPrefixList   = ["v"]
          countType       = "imageCountMoreThan"
          countNumber     = 5
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# ECR Repository for Dashboard container
resource "aws_ecr_repository" "dashboard" {
  name                 = "${var.project_name}-dashboard"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Name = "${var.project_name}-dashboard-repo"
  }
}

# Lifecycle policy for dashboard
resource "aws_ecr_lifecycle_policy" "dashboard" {
  repository = aws_ecr_repository.dashboard.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 5 images, expire untagged images after 7 days"
        selection = {
          tagStatus     = "untagged"
          countType     = "sinceImagePushed"
          countUnit     = "days"
          countNumber   = 7
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Keep last 5 tagged images"
        selection = {
          tagStatus       = "tagged"
          tagPrefixList   = ["v"]
          countType       = "imageCountMoreThan"
          countNumber     = 5
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
