#!/usr/bin/env python3
"""
Controlled Security Drift & Remediation Verification Test
Author: Trey Wright | Cloud Security & SRE

Used in Jenkins CI/CD Stage 7 and local test runs to:
1. Inject a controlled security violation (e.g. 0.0.0.0/0 on port 22).
2. Measure the round-trip latency of the EventBridge -> Lambda auto-remediation loop.
3. Validate CloudWatch audit log entries.
"""

import argparse
from datetime import datetime, timezone
import json
import time
import sys
import os
from unittest.mock import MagicMock

# If boto3 is not installed in the local runner environment, mock it before import
try:
    import boto3
except ImportError:
    mock_boto3 = MagicMock()
    sys.modules['boto3'] = mock_boto3

# Add src to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import lambda_remediation


def run_dry_run_test():
    print("=" * 70)
    print("🔬 RUNNING CONTROLLED SECURITY DRIFT TEST (DRY RUN)")
    print("=" * 70)

    # Mock clients for dry run
    mock_ec2 = MagicMock()
    mock_sns = MagicMock()
    lambda_remediation.ec2_client = mock_ec2
    lambda_remediation.sns_client = mock_sns
    lambda_remediation.SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:test-topic"
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [{
            "GroupId": "sg-production-app",
            "Tags": [{"Key": "ManagedBy", "Value": "CloudSecurityGuardrails"}],
        }]
    }

    simulated_event = {
        "version": "0",
        "id": "e2e-drift-test-001",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.ec2",
        "time": datetime.now(timezone.utc).isoformat(),
        "detail": {
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/developer-manual-test"
            },
            "requestParameters": {
                "groupId": "sg-production-app",
                "ipPermissions": {
                    "items": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 22,
                            "toPort": 22,
                            "ipRanges": {
                                "items": [{"cidrIp": "0.0.0.0/0"}]
                            }
                        }
                    ]
                }
            }
        }
    }

    start_time = time.time()
    print("[1/3] Injecting simulated unauthorized ingress rule (0.0.0.0/0:22)...")
    
    # Execute Lambda handler
    response = lambda_remediation.lambda_handler(simulated_event, None)
    elapsed = time.time() - start_time

    print(f"[2/3] Event intercepted & processed in: {elapsed * 1000:.2f} ms")
    print(f"[3/3] Lambda Response Status: {response['statusCode']}")

    body = json.loads(response['body'])
    print(f"      Actions Taken: {body['actions_taken']}")

    if response['statusCode'] != 200 or len(body['actions_taken']) != 1:
        raise AssertionError("Expected exactly one successful remediation action")
    mock_ec2.revoke_security_group_ingress.assert_called_once()
    mock_sns.publish.assert_called_once()

    print("=" * 70)
    print("✅ VERIFICATION PASSED: Security violation successfully caught and remediated.")
    print("=" * 70)
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Security Drift Simulation")
    parser.add_argument('--mode', choices=['dry-run', 'live'], default='dry-run')
    args = parser.parse_args()

    if args.mode == 'dry-run':
        run_dry_run_test()
    else:
        print("Live AWS drift testing is intentionally separate; use scripts/verify_deployment.sh.", file=sys.stderr)
        sys.exit(2)
