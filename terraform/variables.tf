variable "aws_region" {
  type        = string
  description = "AWS deployment region"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment"
  default     = "lab"
}

variable "base_ami_id" {
  type        = string
  description = "Optional AMI override. Null uses the current Amazon Linux 2023 SSM public parameter."
  default     = null
  nullable    = true
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type for the lab workload"
  default     = "t3.micro"
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the lab VPC"
  default     = "10.0.0.0/16"
}

variable "private_subnet_cidr" {
  type        = string
  description = "CIDR block for the private application subnet"
  default     = "10.0.1.0/24"
}

variable "guardduty_min_severity" {
  type        = number
  description = "Minimum GuardDuty severity that triggers EC2 quarantine"
  default     = 7

  validation {
    condition     = var.guardduty_min_severity >= 0 && var.guardduty_min_severity <= 8.9
    error_message = "guardduty_min_severity must be between 0 and 8.9."
  }
}
