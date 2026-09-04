output "ecr_repository_url" {
  description = "Push the image here"
  value       = aws_ecr_repository.app.repository_url
}

output "codebuild_project" {
  description = "CodeBuild project that builds the image"
  value       = aws_codebuild_project.build.name
}

output "source_bucket" {
  description = "Upload source.zip here for CodeBuild"
  value       = aws_s3_bucket.source.bucket
}

output "service_url" {
  description = "Public App Runner URL (once deploy_service = true)"
  value       = var.deploy_service ? "https://${aws_apprunner_service.app[0].service_url}" : "(set deploy_service=true and re-apply)"
}
