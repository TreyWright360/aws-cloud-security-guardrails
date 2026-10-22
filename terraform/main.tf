terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "CloudSecurityGuardrails"
      Environment = var.environment
      ManagedBy   = "CloudSecurityGuardrails"
      Owner       = "TreyWright"
    }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ssm_parameter" "amazon_linux_2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

locals {
  base_ami_id = coalesce(var.base_ami_id, data.aws_ssm_parameter.amazon_linux_2023.value)
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "sec-hardened-vpc" }
}

resource "aws_subnet" "private_app" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.private_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = { Name = "sec-private-app-subnet" }
}

resource "aws_kms_key" "ebs_key" {
  description             = "Customer-managed key for hardened EBS encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = { Name = "sec-ebs-cmk" }
}

resource "aws_kms_alias" "ebs_key" {
  name          = "alias/cloud-security-guardrails-ebs"
  target_key_id = aws_kms_key.ebs_key.key_id
}

resource "aws_security_group" "app_sg" {
  name        = "sec-app-workload-sg"
  description = "Private workload; managed with SSM and no inbound internet access"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "HTTPS to private AWS service endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = { Name = "sec-app-workload-sg" }
}

resource "aws_security_group" "endpoint_sg" {
  name        = "sec-vpc-endpoint-sg"
  description = "Accept HTTPS from the managed workload security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "HTTPS from managed workloads"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }

  tags = { Name = "sec-vpc-endpoint-sg" }
}

resource "aws_security_group" "quarantine_sg" {
  name        = "sec-quarantine-sg"
  description = "Isolation group with no ingress or egress rules"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "sec-quarantine-isolated-sg" }
}

resource "aws_vpc_endpoint" "ssm_services" {
  for_each = toset(["ssm", "ssmmessages", "ec2messages", "logs"])

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [aws_subnet.private_app.id]
  security_group_ids  = [aws_security_group.endpoint_sg.id]

  tags = { Name = "sec-${each.value}-endpoint" }
}

resource "aws_iam_role" "ssm_instance_role" {
  name = "sec-ec2-ssm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ssm_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm_profile" {
  name = "sec-ec2-ssm-instance-profile"
  role = aws_iam_role.ssm_instance_role.name
}

resource "aws_instance" "hardened_node" {
  ami                    = local.base_ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.private_app.id
  iam_instance_profile   = aws_iam_instance_profile.ssm_profile.name
  vpc_security_group_ids = [aws_security_group.app_sg.id]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.ebs_key.arn
    volume_type = "gp3"
    volume_size = 20
  }

  tags = {
    Name           = "sec-hardened-workload-node"
    SecurityStatus = "BaselineApplied"
  }

  depends_on = [aws_vpc_endpoint.ssm_services]
}
