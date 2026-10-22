"""Event-driven AWS security-group remediation and instance quarantine.

The handler is invoked by EventBridge for CloudTrail security-group changes and
optionally for high-severity GuardDuty EC2 findings. It only changes resources
that carry the configured management tag.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Iterable, List, Optional

import boto3

try:
    from botocore.exceptions import ClientError
except ImportError:  # Allows dependency-free local unit tests with mocked boto3.
    class ClientError(Exception):
        response: Dict[str, Any] = {}

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client("ec2")
sns_client = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
QUARANTINE_SG_ID = os.environ.get("QUARANTINE_SG_ID", "")
MANAGED_TAG_KEY = os.environ.get("MANAGED_TAG_KEY", "ManagedBy")
MANAGED_TAG_VALUE = os.environ.get("MANAGED_TAG_VALUE", "CloudSecurityGuardrails")
GUARDDUTY_MIN_SEVERITY = float(os.environ.get("GUARDDUTY_MIN_SEVERITY", "7.0"))
PROHIBITED_PORTS = frozenset({22, 3389, 5432, 3306, 1433})
PUBLIC_IPV4 = "0.0.0.0/0"
PUBLIC_IPV6 = "::/0"


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Evaluate an EventBridge event and execute the required remediation."""
    audit("event_received", event_id=event.get("id"), source=event.get("source"))
    detail = event.get("detail") or {}
    event_name = detail.get("eventName", "")

    if event_name == "AuthorizeSecurityGroupIngress":
        actions = handle_security_group_ingress(detail)
    elif is_guardduty_ec2_finding(event):
        actions = handle_instance_quarantine(detail)
    elif event_name in {"GuardDutyFinding", "IsolateInstanceRequest"}:
        actions = handle_instance_quarantine(detail)
    elif event.get("source") == "custom.security.drift":
        actions = handle_custom_drift(detail)
    else:
        actions = []
        audit("event_ignored", event_name=event_name)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {"message": "Security evaluation completed", "actions_taken": actions}
        ),
    }


def is_guardduty_ec2_finding(event: Dict[str, Any]) -> bool:
    """Return True for actionable, high-severity GuardDuty EC2 findings."""
    if event.get("source") != "aws.guardduty":
        return False
    if event.get("detail-type") != "GuardDuty Finding":
        return False
    detail = event.get("detail") or {}
    instance_id = (
        detail.get("resource", {}).get("instanceDetails", {}).get("instanceId")
    )
    return bool(instance_id and float(detail.get("severity", 0)) >= GUARDDUTY_MIN_SEVERITY)


def handle_security_group_ingress(detail: Dict[str, Any]) -> List[str]:
    """Revoke public ingress that exposes a prohibited administrative port."""
    request_params = detail.get("requestParameters") or {}
    sg_id = request_params.get("groupId")
    permissions = (request_params.get("ipPermissions") or {}).get("items") or []
    if not sg_id or not permissions:
        return []

    violating_permissions = [
        boto3_permission_for_public_ranges(permission)
        for permission in permissions
        if permission_exposes_prohibited_port(permission)
    ]
    violating_permissions = [permission for permission in violating_permissions if permission]
    if not violating_permissions:
        return []

    if not resource_has_management_tag("security-group", sg_id):
        audit("security_group_ignored_unmanaged", security_group_id=sg_id)
        return []

    actions: List[str] = []
    for permission in violating_permissions:
        try:
            ec2_client.revoke_security_group_ingress(
                GroupId=sg_id, IpPermissions=[permission]
            )
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code")
            if error_code == "InvalidPermission.NotFound":
                audit("security_group_rule_already_absent", security_group_id=sg_id)
                continue
            raise
        except Exception:
            logger.exception("Mandatory security-group remediation failed")
            raise

        description = describe_permission(permission)
        action = f"Revoked public ingress {description} on security group {sg_id}"
        actions.append(action)
        audit("security_group_rule_revoked", security_group_id=sg_id, rule=description)

    if actions:
        publish_alert("SECURITY DRIFT REMEDIATED", "\n".join(actions), detail)
    return actions


def permission_exposes_prohibited_port(permission: Dict[str, Any]) -> bool:
    """Detect public IPv4/IPv6 rules covering any prohibited port."""
    public = any(
        item.get("cidrIp") == PUBLIC_IPV4
        for item in (permission.get("ipRanges") or {}).get("items", [])
    ) or any(
        item.get("cidrIpv6") == PUBLIC_IPV6
        for item in (permission.get("ipv6Ranges") or {}).get("items", [])
    )
    if not public:
        return False

    protocol = str(permission.get("ipProtocol", ""))
    if protocol == "-1":
        return True
    if protocol not in {"tcp", "6"}:
        return False

    from_port = permission.get("fromPort")
    to_port = permission.get("toPort")
    if from_port is None or to_port is None:
        return False
    return any(from_port <= port <= to_port for port in PROHIBITED_PORTS)


def boto3_permission_for_public_ranges(
    permission: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Translate a CloudTrail permission into a precise boto3 revoke request."""
    ipv4_ranges = [
        {"CidrIp": item["cidrIp"]}
        for item in (permission.get("ipRanges") or {}).get("items", [])
        if item.get("cidrIp") == PUBLIC_IPV4
    ]
    ipv6_ranges = [
        {"CidrIpv6": item["cidrIpv6"]}
        for item in (permission.get("ipv6Ranges") or {}).get("items", [])
        if item.get("cidrIpv6") == PUBLIC_IPV6
    ]
    if not ipv4_ranges and not ipv6_ranges:
        return None

    result: Dict[str, Any] = {"IpProtocol": str(permission.get("ipProtocol", "-1"))}
    if result["IpProtocol"] != "-1":
        result["FromPort"] = permission["fromPort"]
        result["ToPort"] = permission["toPort"]
    if ipv4_ranges:
        result["IpRanges"] = ipv4_ranges
    if ipv6_ranges:
        result["Ipv6Ranges"] = ipv6_ranges
    return result


def describe_permission(permission: Dict[str, Any]) -> str:
    cidrs = [item["CidrIp"] for item in permission.get("IpRanges", [])]
    cidrs.extend(item["CidrIpv6"] for item in permission.get("Ipv6Ranges", []))
    if permission["IpProtocol"] == "-1":
        port_description = "all protocols"
    else:
        port_description = f"ports {permission['FromPort']}-{permission['ToPort']}"
    return f"{','.join(cidrs)} {port_description}"


def resource_has_management_tag(resource_type: str, resource_id: str) -> bool:
    """Limit account-wide events to resources owned by this project."""
    if resource_type == "security-group":
        response = ec2_client.describe_security_groups(GroupIds=[resource_id])
        resources = response.get("SecurityGroups", [])
    elif resource_type == "instance":
        response = ec2_client.describe_instances(InstanceIds=[resource_id])
        resources = [
            instance
            for reservation in response.get("Reservations", [])
            for instance in reservation.get("Instances", [])
        ]
    else:
        return False

    return any(
        tag.get("Key") == MANAGED_TAG_KEY and tag.get("Value") == MANAGED_TAG_VALUE
        for resource in resources
        for tag in resource.get("Tags", [])
    )


def handle_instance_quarantine(detail: Dict[str, Any]) -> List[str]:
    """Isolate a managed EC2 instance and snapshot its root EBS volume."""
    instance_id = detail.get("instanceId") or (
        detail.get("resource", {}).get("instanceDetails", {}).get("instanceId")
    )
    if not instance_id:
        return []

    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    instances = [
        instance
        for reservation in response.get("Reservations", [])
        for instance in reservation.get("Instances", [])
    ]
    if not instances:
        raise RuntimeError(f"Instance {instance_id} was not found")
    instance = instances[0]

    # Legacy tests and manual events may omit tags; GuardDuty events are tag-scoped.
    if detail.get("resource") and not has_management_tag(instance.get("Tags", [])):
        audit("instance_ignored_unmanaged", instance_id=instance_id)
        return []
    if not QUARANTINE_SG_ID:
        raise RuntimeError("QUARANTINE_SG_ID is not configured")

    actions: List[str] = []
    interfaces = instance.get("NetworkInterfaces", [])
    if interfaces:
        for interface in interfaces:
            ec2_client.modify_network_interface_attribute(
                NetworkInterfaceId=interface["NetworkInterfaceId"],
                Groups=[QUARANTINE_SG_ID],
            )
    else:
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id, Groups=[QUARANTINE_SG_ID]
        )
    actions.append(f"Isolated instance {instance_id} with {QUARANTINE_SG_ID}")

    ec2_client.create_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": "SecurityStatus", "Value": "Quarantined"},
            {"Key": "IncidentTimestamp", "Value": str(detail.get("eventTime", ""))},
        ],
    )
    actions.append(f"Tagged instance {instance_id} as quarantined")

    root_device_name = instance.get("RootDeviceName")
    root_volume_id = next(
        (
            device.get("Ebs", {}).get("VolumeId")
            for device in instance.get("BlockDeviceMappings", [])
            if device.get("DeviceName") == root_device_name
        ),
        None,
    )
    if not root_volume_id:
        raise RuntimeError(f"Root EBS volume for {instance_id} was not found")

    snapshot = ec2_client.create_snapshot(
        VolumeId=root_volume_id,
        Description=f"Forensic snapshot for quarantined instance {instance_id}",
    )
    actions.append(
        f"Created root-volume snapshot {snapshot.get('SnapshotId')} from {root_volume_id}"
    )
    audit("instance_quarantined", instance_id=instance_id, actions=actions)
    publish_alert("INSTANCE QUARANTINED", "\n".join(actions), detail)
    return actions


def has_management_tag(tags: Iterable[Dict[str, str]]) -> bool:
    return any(
        tag.get("Key") == MANAGED_TAG_KEY and tag.get("Value") == MANAGED_TAG_VALUE
        for tag in tags
    )


def handle_custom_drift(detail: Dict[str, Any]) -> List[str]:
    """Handle a non-AWS local smoke-test event without mutating resources."""
    action = f"Controlled test event acknowledged: {detail.get('description', '')}"
    audit("controlled_test_event", description=detail.get("description", ""))
    return [action]


def publish_alert(subject: str, message: str, raw_event: Dict[str, Any]) -> None:
    """Publish an optional SNS alert. Failures surface for retry and DLQ handling."""
    audit("alert_requested", subject=subject, message=message)
    if not SNS_TOPIC_ARN:
        return
    payload = {
        "alert": subject,
        "remediation_details": message,
        "event_source": raw_event.get("eventSource", "aws.security"),
        "user_identity": raw_event.get("userIdentity", {}).get("arn", "unknown"),
    }
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[SEC-OPS] {subject}"[:100],
        Message=json.dumps(payload, sort_keys=True),
    )


def audit(action: str, **fields: Any) -> None:
    """Write a structured JSON audit record to CloudWatch Logs."""
    logger.info(json.dumps({"action": action, **fields}, default=str, sort_keys=True))
