# Copy to terraform.tfvars and adjust if needed.
aws_region     = "us-east-1"
project        = "ksi-harness-web"
image_tag      = "latest"
app_cpu        = "1024"
app_memory     = "2048"

# Leave false for the first apply; the deploy script flips it to true after the image is built
# and pushed.
deploy_service = false
