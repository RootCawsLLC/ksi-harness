locals {
  ecr_registry = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com"
}

resource "aws_codebuild_project" "build" {
  name          = "${var.project}-build"
  description   = "Builds the ksi-harness web Dockerfile and pushes to ECR"
  service_role  = aws_iam_role.codebuild.arn
  build_timeout = 30

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type    = "BUILD_GENERAL1_SMALL"
    image           = "aws/codebuild/standard:7.0"
    type            = "LINUX_CONTAINER"
    privileged_mode = true # required to run docker build

    environment_variable {
      name  = "AWS_REGION"
      value = var.aws_region
    }
    environment_variable {
      name  = "ECR_REGISTRY"
      value = local.ecr_registry
    }
    environment_variable {
      name  = "ECR_REPO"
      value = aws_ecr_repository.app.repository_url
    }
    environment_variable {
      name  = "IMAGE_TAG"
      value = var.image_tag
    }
  }

  source {
    type = "S3"
    # The ksi-harness repo is packaged at its root; the Dockerfile lives at web/Dockerfile and
    # its build context is the repo root.
    location  = "${aws_s3_bucket.source.bucket}/source.zip"
    buildspec = <<-EOT
      version: 0.2
      phases:
        pre_build:
          commands:
            - echo Logging in to ECR...
            - aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ECR_REGISTRY
        build:
          commands:
            - echo Building image $ECR_REPO:$IMAGE_TAG
            - docker build -f web/Dockerfile -t $ECR_REPO:$IMAGE_TAG .
        post_build:
          commands:
            - echo Pushing image...
            - docker push $ECR_REPO:$IMAGE_TAG
            - echo Done.
    EOT
  }

  logs_config {
    cloudwatch_logs {
      group_name = "/aws/codebuild/${var.project}"
    }
  }
}
