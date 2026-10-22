terraform {
  # Jenkins supplies the environment-specific S3 settings from ci/backend-prod.hcl.
  # Local validation uses `terraform init -backend=false`.
  backend "s3" {}
}
