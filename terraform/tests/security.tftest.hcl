mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = { names = ["us-east-1a"] }
  }

  mock_data "aws_ssm_parameter" {
    defaults = { value = "ami-0123456789abcdef0" }
  }

  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }

  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }

  mock_resource "aws_kms_key" {
    defaults = {
      arn    = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
      key_id = "00000000-0000-0000-0000-000000000000"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn  = "arn:aws:iam::123456789012:role/mock-role"
      name = "mock-role"
    }
  }

  mock_resource "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::123456789012:policy/mock-remediation" }
  }

  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:us-east-1:123456789012:mock-alerts" }
  }

  mock_resource "aws_sqs_queue" {
    defaults = {
      arn  = "arn:aws:sqs:us-east-1:123456789012:mock-dlq"
      id   = "https://sqs.us-east-1.amazonaws.com/123456789012/mock-dlq"
      name = "mock-dlq"
    }
  }

  mock_resource "aws_cloudwatch_event_rule" {
    defaults = {
      arn  = "arn:aws:events:us-east-1:123456789012:rule/mock-rule"
      name = "mock-rule"
    }
  }

  mock_resource "aws_lambda_function" {
    defaults = {
      arn           = "arn:aws:lambda:us-east-1:123456789012:function:mock-remediation"
      function_name = "mock-remediation"
    }
  }
}

mock_provider "archive" {
  mock_data "archive_file" {
    defaults = {
      output_path         = "lambda_payload.zip"
      output_base64sha256 = "bW9ja2hhc2g="
    }
  }
}

run "security_baseline" {
  command = apply

  assert {
    condition     = aws_subnet.private_app.map_public_ip_on_launch == false
    error_message = "Private subnet must not assign public IP addresses."
  }

  assert {
    condition     = aws_instance.hardened_node.metadata_options[0].http_tokens == "required"
    error_message = "EC2 must require IMDSv2 tokens."
  }

  assert {
    condition     = aws_instance.hardened_node.root_block_device[0].encrypted == true
    error_message = "The EC2 root volume must be encrypted."
  }

  assert {
    condition     = length(aws_security_group.app_sg.ingress) == 0
    error_message = "The workload security group must not define inbound rules."
  }

  assert {
    condition     = aws_cloudtrail.management_events.is_multi_region_trail == true
    error_message = "CloudTrail must capture management events across regions."
  }

  assert {
    condition     = aws_lambda_function.remediation_engine.environment[0].variables["MANAGED_TAG_VALUE"] == "CloudSecurityGuardrails"
    error_message = "Lambda must enforce the project management-tag boundary."
  }
}
