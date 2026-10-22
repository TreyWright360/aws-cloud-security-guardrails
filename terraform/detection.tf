data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  trail_bucket_name = "cloud-security-guardrails-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
}

resource "aws_kms_key" "audit_key" {
  description             = "Customer-managed key for CloudTrail, S3 audit logs, and SNS alerts"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableAccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudTrailEncryption"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = ["kms:DescribeKey", "kms:GenerateDataKey*"]
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/sec-management-events" }
        }
      },
      {
        Sid       = "AllowSNSAndCloudWatch"
        Effect    = "Allow"
        Principal = { Service = ["sns.amazonaws.com", "cloudwatch.amazonaws.com"] }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
      }
    ]
  })

  tags = { Name = "sec-audit-alerts-cmk" }
}

resource "aws_kms_alias" "audit_key" {
  name          = "alias/cloud-security-guardrails-audit"
  target_key_id = aws_kms_key.audit_key.key_id
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = local.trail_bucket_name
  force_destroy = false

  tags = { Name = "sec-cloudtrail-audit" }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.audit_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
        Condition = {
          StringEquals = { "AWS:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/sec-management-events" }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "AWS:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/sec-management-events"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "management_events" {
  name                          = "sec-management-events"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.audit_key.arn

  event_selector {
    read_write_type           = "WriteOnly"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

resource "aws_sns_topic" "security_alerts" {
  name              = "sec-ops-incident-alerts"
  kms_master_key_id = aws_kms_key.audit_key.arn

  tags = { Name = "sec-ops-alerts" }
}

resource "aws_cloudwatch_log_group" "remediation_logs" {
  name              = "/aws/lambda/sec-auto-remediation-engine"
  retention_in_days = 90

  tags = { Name = "sec-remediation-audit-logs" }
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/lambda_remediation.py"
  output_path = "${path.module}/lambda_payload.zip"
}

resource "aws_iam_role" "lambda_exec_role" {
  name = "sec-remediation-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_policy" "lambda_remediation_policy" {
  name        = "sec-remediation-runtime-policy"
  description = "Runtime permissions for tagged security-group remediation and EC2 quarantine"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadEC2State"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups"
        ]
        Resource = "*"
      },
      {
        Sid    = "RemediateEC2"
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:RevokeSecurityGroupIngress"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchLogging"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.remediation_logs.arn}:*"
      },
      {
        Sid      = "SNSAlerting"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Sid    = "SNSManagedKeyUsage"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.audit_key.arn
        Condition = {
          StringEquals = { "kms:ViaService" = "sns.${var.aws_region}.amazonaws.com" }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_attach" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.lambda_remediation_policy.arn
}

resource "aws_lambda_function" "remediation_engine" {
  function_name    = "sec-auto-remediation-engine"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "lambda_remediation.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      GUARDDUTY_MIN_SEVERITY = tostring(var.guardduty_min_severity)
      MANAGED_TAG_KEY        = "ManagedBy"
      MANAGED_TAG_VALUE      = "CloudSecurityGuardrails"
      QUARANTINE_SG_ID       = aws_security_group.quarantine_sg.id
      SNS_TOPIC_ARN          = aws_sns_topic.security_alerts.arn
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.remediation_logs,
    aws_iam_role_policy_attachment.lambda_attach
  ]

  tags = { Name = "sec-auto-remediation-engine" }
}

resource "aws_sqs_queue" "eventbridge_dlq" {
  name                      = "sec-remediation-eventbridge-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue_policy" "eventbridge_dlq" {
  queue_url = aws_sqs_queue.eventbridge_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgeDLQ"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.eventbridge_dlq.arn
      Condition = {
        ArnLike = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/sec-*" }
      }
    }]
  })
}

resource "aws_cloudwatch_event_rule" "sg_ingress_drift" {
  name        = "sec-detect-unauthorized-ingress"
  description = "Capture security-group ingress authorization API calls from CloudTrail"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress"]
    }
  })
}

resource "aws_cloudwatch_event_rule" "guardduty_ec2" {
  name        = "sec-detect-high-severity-guardduty-ec2"
  description = "Forward GuardDuty EC2 findings to the quarantine handler"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      resource = { resourceType = ["Instance"] }
    }
  })
}

resource "aws_cloudwatch_event_target" "sg_ingress_lambda" {
  rule      = aws_cloudwatch_event_rule.sg_ingress_drift.name
  target_id = "TriggerSecurityGroupRemediation"
  arn       = aws_lambda_function.remediation_engine.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }

  dead_letter_config { arn = aws_sqs_queue.eventbridge_dlq.arn }
}

resource "aws_cloudwatch_event_target" "guardduty_lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_ec2.name
  target_id = "TriggerInstanceQuarantine"
  arn       = aws_lambda_function.remediation_engine.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }

  dead_letter_config { arn = aws_sqs_queue.eventbridge_dlq.arn }
}

resource "aws_lambda_permission" "allow_sg_eventbridge" {
  statement_id  = "AllowSecurityGroupEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation_engine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sg_ingress_drift.arn
}

resource "aws_lambda_permission" "allow_guardduty_eventbridge" {
  statement_id  = "AllowGuardDutyEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation_engine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_ec2.arn
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "sec-remediation-lambda-errors"
  alarm_description   = "Auto-remediation Lambda reported an execution error"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  dimensions = { FunctionName = aws_lambda_function.remediation_engine.function_name }
}

resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  alarm_name          = "sec-remediation-dlq-messages"
  alarm_description   = "EventBridge exhausted retries and placed an event in the DLQ"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  dimensions = { QueueName = aws_sqs_queue.eventbridge_dlq.name }
}
