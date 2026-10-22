"""
Unit Tests for Cloud Security Auto-Remediation Lambda
Author: Trey Wright | Cloud Security & SRE
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# If boto3 is not installed in the local runner environment, mock it before import
try:
    import boto3
except ImportError:
    mock_boto3 = MagicMock()
    sys.modules['boto3'] = mock_boto3

# Add src to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import lambda_remediation


class TestSecurityRemediation(unittest.TestCase):

    def setUp(self):
        lambda_remediation.SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:test-topic'
        lambda_remediation.QUARANTINE_SG_ID = 'sg-quarantine123'
        self.mock_ec2 = MagicMock()
        self.mock_sns = MagicMock()
        lambda_remediation.ec2_client = self.mock_ec2
        lambda_remediation.sns_client = self.mock_sns
        self.mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-appworkload123",
                "Tags": [{"Key": "ManagedBy", "Value": "CloudSecurityGuardrails"}],
            }]
        }

    def test_revoke_unauthorized_port_22_ingress(self):
        """Verify that an ingress rule opening port 22 to 0.0.0.0/0 is immediately revoked."""
        event = {
            "version": "0",
            "id": "test-event-1",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.ec2",
            "detail": {
                "eventSource": "ec2.amazonaws.com",
                "eventName": "AuthorizeSecurityGroupIngress",
                "requestParameters": {
                    "groupId": "sg-appworkload123",
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

        response = lambda_remediation.lambda_handler(event, None)
        self.assertEqual(response['statusCode'], 200)

        # Assert ec2_client.revoke_security_group_ingress was called
        self.mock_ec2.revoke_security_group_ingress.assert_called_once()
        call_kwargs = self.mock_ec2.revoke_security_group_ingress.call_args[1]
        self.assertEqual(call_kwargs['GroupId'], 'sg-appworkload123')
        self.assertEqual(call_kwargs['IpPermissions'], [{
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
        }])

        # Assert SNS alert was dispatched
        self.mock_sns.publish.assert_called_once()

    def test_ignore_compliant_ingress_rule(self):
        """Verify that compliant internal rules (e.g. 10.0.0.0/16) are not revoked."""
        event = {
            "detail": {
                "eventName": "AuthorizeSecurityGroupIngress",
                "requestParameters": {
                    "groupId": "sg-appworkload123",
                    "ipPermissions": {
                        "items": [
                            {
                                "ipProtocol": "tcp",
                                "fromPort": 443,
                                "toPort": 443,
                                "ipRanges": {
                                    "items": [{"cidrIp": "10.0.0.0/16"}]
                                }
                            }
                        ]
                    }
                }
            }
        }

        response = lambda_remediation.lambda_handler(event, None)
        self.assertEqual(response['statusCode'], 200)

        # Ensure no revocation or alert occurred
        self.mock_ec2.revoke_security_group_ingress.assert_not_called()
        self.mock_sns.publish.assert_not_called()

    def test_quarantine_instance_and_snapshot(self):
        """Verify that an isolation request replaces SG with quarantine-sg and creates an EBS snapshot."""
        self.mock_ec2.describe_instances.return_value = {
            "Reservations": [{
                "Instances": [{
                    "InstanceId": "i-compromised123",
                    "Tags": [
                        {"Key": "ManagedBy", "Value": "CloudSecurityGuardrails"}
                    ],
                    "RootDeviceName": "/dev/xvda",
                    "BlockDeviceMappings": [{
                        "DeviceName": "/dev/xvda",
                        "Ebs": {"VolumeId": "vol-root123"}
                    }]
                }]
            }]
        }
        self.mock_ec2.create_snapshot.return_value = {"SnapshotId": "snap-forensic123"}

        event = {
            "source": "aws.guardduty",
            "detail-type": "GuardDuty Finding",
            "detail": {
                "severity": 8.0,
                "resource": {
                    "instanceDetails": {"instanceId": "i-compromised123"}
                }
            }
        }

        response = lambda_remediation.lambda_handler(event, None)
        self.assertEqual(response['statusCode'], 200)

        # Assert quarantine SG was attached
        self.mock_ec2.modify_instance_attribute.assert_called_once_with(
            InstanceId='i-compromised123',
            Groups=['sg-quarantine123']
        )

        # Assert instance tagged
        self.mock_ec2.create_tags.assert_called_once()

        # Assert forensic snapshot taken
        self.mock_ec2.create_snapshot.assert_called_once_with(
            VolumeId='vol-root123',
            Description='Forensic snapshot for quarantined instance i-compromised123'
        )

    def test_revoke_range_that_contains_prohibited_port(self):
        """A broad public range must not bypass the prohibited-port policy."""
        event = {
            "detail": {
                "eventName": "AuthorizeSecurityGroupIngress",
                "requestParameters": {
                    "groupId": "sg-appworkload123",
                    "ipPermissions": {"items": [{
                        "ipProtocol": "tcp",
                        "fromPort": 0,
                        "toPort": 65535,
                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                    }]},
                },
            }
        }

        lambda_remediation.lambda_handler(event, None)

        self.mock_ec2.revoke_security_group_ingress.assert_called_once()

    def test_revoke_public_ipv6_prohibited_port(self):
        """Public IPv6 ingress is subject to the same policy as IPv4."""
        event = {
            "detail": {
                "eventName": "AuthorizeSecurityGroupIngress",
                "requestParameters": {
                    "groupId": "sg-appworkload123",
                    "ipPermissions": {"items": [{
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "toPort": 22,
                        "ipv6Ranges": {"items": [{"cidrIpv6": "::/0"}]},
                    }]},
                },
            }
        }

        lambda_remediation.lambda_handler(event, None)

        self.mock_ec2.revoke_security_group_ingress.assert_called_once()

    def test_ignore_untagged_security_group(self):
        """The account-wide EventBridge rule must not mutate unmanaged resources."""
        self.mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{"GroupId": "sg-appworkload123", "Tags": []}]
        }
        event = {
            "detail": {
                "eventName": "AuthorizeSecurityGroupIngress",
                "requestParameters": {
                    "groupId": "sg-appworkload123",
                    "ipPermissions": {"items": [{
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "toPort": 22,
                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                    }]},
                },
            }
        }

        response = lambda_remediation.lambda_handler(event, None)

        self.mock_ec2.revoke_security_group_ingress.assert_not_called()
        self.assertEqual(json.loads(response["body"])["actions_taken"], [])

    def test_revocation_failure_is_raised_for_eventbridge_retry(self):
        """Mandatory remediation failures must not be acknowledged as success."""
        self.mock_ec2.revoke_security_group_ingress.side_effect = RuntimeError("AWS failure")
        event = {
            "detail": {
                "eventName": "AuthorizeSecurityGroupIngress",
                "requestParameters": {
                    "groupId": "sg-appworkload123",
                    "ipPermissions": {"items": [{
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "toPort": 22,
                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                    }]},
                },
            }
        }

        with self.assertRaises(RuntimeError):
            lambda_remediation.lambda_handler(event, None)


if __name__ == '__main__':
    unittest.main()
