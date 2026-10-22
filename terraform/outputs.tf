output "vpc_id" {
  description = "ID of the hardened VPC"
  value       = aws_vpc.main.id
}

output "hardened_instance_id" {
  description = "ID of the hardened EC2 instance"
  value       = aws_instance.hardened_node.id
}

output "app_security_group_id" {
  description = "ID of the managed application security group"
  value       = aws_security_group.app_sg.id
}

output "quarantine_security_group_id" {
  description = "ID of the quarantine security group"
  value       = aws_security_group.quarantine_sg.id
}

output "lambda_function_arn" {
  description = "ARN of the auto-remediation Lambda function"
  value       = aws_lambda_function.remediation_engine.arn
}

output "eventbridge_rule_name" {
  description = "Name of the security-group drift detection rule"
  value       = aws_cloudwatch_event_rule.sg_ingress_drift.name
}

output "sns_alerts_topic_arn" {
  description = "ARN of the SNS security alerts extension point"
  value       = aws_sns_topic.security_alerts.arn
}

output "cloudtrail_name" {
  description = "CloudTrail trail feeding AWS API events to EventBridge"
  value       = aws_cloudtrail.management_events.name
}
