variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Name prefix for all resources"
  type        = string
  default     = "ksi-harness-web"
}

variable "image_tag" {
  description = "Container image tag in ECR to deploy"
  type        = string
  default     = "latest"
}

variable "deploy_service" {
  description = "Create the App Runner service. false for the first apply (before the image exists), true after the image is pushed."
  type        = bool
  default     = false
}

variable "app_cpu" {
  description = "App Runner vCPU (1024 = 1 vCPU). The run collects fixtures, builds state and emits artifacts in-process; 1 vCPU is ample."
  type        = string
  default     = "1024"
}

variable "app_memory" {
  description = "App Runner memory (2048 = 2 GB)"
  type        = string
  default     = "2048"
}
