# This file contains additional IAM policies and role details.
# Most IAM resources are defined in their respective module files:
# - ECS task execution and task roles: ecs.tf
# - VPC Flow Logs role: vpc.tf

# Policy: Least-privilege S3 access for ECS tasks
# (Defined in ecs.tf as aws_iam_role_policy.ecs_task_s3)

# Policy: Least-privilege Secrets Manager access for ECS tasks
# (Defined in ecs.tf as aws_iam_role_policy.ecs_task_secrets)

# Policy: Least-privilege ECR and Secrets Manager access for task execution
# (Defined in ecs.tf as aws_iam_role_policy.ecs_task_execution_ecr_secrets)

# ===== Data sources for account information =====
# Note: aws_caller_identity.current is defined in main.tf

# ===== Policy: Deny root user actions (optional, for extra security) =====
# Uncomment below to enforce additional guardrails

# resource "aws_iam_policy" "deny_root_actions" {
#   name_prefix = "deny-root-"
#   description = "Deny high-risk root account actions"

#   policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Sid    = "DenyRootAccess"
#         Effect = "Deny"
#         Action = [
#           "iam:*",
#           "ec2:TerminateInstances",
#           "rds:DeleteDBInstance"
#         ]
#         Resource = "*"
#         Principal = {
#           AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
#         }
#       }
#     ]
#   })
# }

# ===== Service-linked role checks (informational) =====

# For ECS Fargate, AWS automatically creates service-linked roles if needed:
# - AWSServiceRoleForECS
# - AWSServiceRoleForApplicationAutoScaling
# - AWSServiceRoleForRDS

# These are created on-demand and do not need explicit definition in Terraform.
