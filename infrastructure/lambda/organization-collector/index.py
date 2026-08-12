"""Gatewatch organization-scale security-group collector.

The same artifact backs three Lambda handlers:
* discovery_handler enumerates active organization accounts and creates a run.
* worker_handler scans one account with bounded regional concurrency.
* finalizer_handler publishes an immutable manifest and the latest pointer.

Workers never assemble an organization-wide document in memory. Each successful
account/Region scan becomes an independently checksummed S3 evidence shard.
"""

from __future__ import annotations

import base64
import concurrent.futures
import gzip
import hashlib
import json
import logging
import os
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

EVIDENCE_BUCKET = os.environ["EVIDENCE_BUCKET"]
KMS_KEY_ARN = os.environ["KMS_KEY_ARN"]
RUN_TABLE = os.environ["RUN_TABLE"]
MEMBER_ROLE_NAME = os.environ.get("MEMBER_ROLE_NAME", "GatewatchSecurityGroupReadRole")
PARTITION = os.environ.get("PARTITION", "aws")
SOURCE_ACCOUNT_ID = os.environ.get("SOURCE_ACCOUNT_ID", "")
SOURCE_REGION = os.environ.get("SOURCE_REGION", "us-east-1")
ORGANIZATION_TARGET_IDS = tuple(
    value.strip()
    for value in os.environ.get("ORGANIZATION_TARGET_IDS", "").split(",")
    if value.strip()
)
EXCLUDED_ACCOUNT_IDS = {
    value.strip()
    for value in os.environ.get("EXCLUDED_ACCOUNT_IDS", "").split(",")
    if value.strip()
}
REGION_ALLOW_LIST = {
    value.strip()
    for value in os.environ.get("REGION_ALLOW_LIST", "").split(",")
    if value.strip()
}
MAX_REGION_CONCURRENCY = max(
    1, min(8, int(os.environ.get("MAX_REGION_CONCURRENCY", "4")))
)

SDK_CONFIG = Config(
    connect_timeout=5,
    read_timeout=60,
    retries={"max_attempts": 8, "mode": "adaptive"},
    user_agent_extra="GatewatchOrganizationCollector/2.0",
)
RUN_ID_PATTERN = re.compile(r"^[a-f0-9-]{36}$")
ACCOUNT_ID_PATTERN = re.compile(r"^[0-9]{12}$")
REGION_PATTERN = re.compile(r"^[a-z0-9-]+-[0-9]$")


def utc_now():
    return datetime.now(timezone.utc)


def isoformat(value=None):
    return (value or utc_now()).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def tags_to_dict(tags):
    return {
        item["Key"]: item.get("Value", "")
        for item in (tags or [])
        if isinstance(item, dict) and item.get("Key")
    }


def clean_error(error):
    if isinstance(error, ClientError):
        payload = error.response.get("Error", {})
        return {
            "code": str(payload.get("Code", "ClientError"))[:120],
            "message": str(payload.get("Message", "AWS API request failed"))[:500],
        }
    return {
        "code": error.__class__.__name__[:120],
        "message": str(error)[:500],
    }


def paginate(client, operation_name, result_key, **kwargs):
    paginator = client.get_paginator(operation_name)
    for page in paginator.paginate(**kwargs):
        yield from page.get(result_key, [])


def put_json(key, value, *, compress=False, metadata=None):
    canonical = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    checksum = hashlib.sha256(canonical).hexdigest()
    body = gzip.compress(canonical, compresslevel=6) if compress else canonical
    request = {
        "Bucket": EVIDENCE_BUCKET,
        "Key": key,
        "Body": body,
        "ContentType": "application/json",
        "ServerSideEncryption": "aws:kms",
        "SSEKMSKeyId": KMS_KEY_ARN,
        "ChecksumSHA256": base64.b64encode(hashlib.sha256(body).digest()).decode("ascii"),
        "Metadata": {"canonical-sha256": checksum, **(metadata or {})},
    }
    if compress:
        request["ContentEncoding"] = "gzip"
    boto3.client("s3", config=SDK_CONFIG).put_object(**request)
    return {"key": key, "sha256": checksum, "bytes": len(body)}


def table():
    return boto3.resource("dynamodb", config=SDK_CONFIG).Table(RUN_TABLE)


def run_key(run_id):
    if not RUN_ID_PATTERN.fullmatch(run_id or ""):
        raise ValueError("Invalid collection run ID")
    return f"RUN#{run_id}"


def update_item(run_id, target_id, values):
    names = {f"#n{index}": name for index, name in enumerate(values)}
    expressions = []
    expression_values = {}
    for index, (name, value) in enumerate(values.items()):
        expressions.append(f"#n{index} = :v{index}")
        expression_values[f":v{index}"] = value
    table().update_item(
        Key={"runKey": run_key(run_id), "targetKey": target_id},
        UpdateExpression="SET " + ", ".join(expressions),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=expression_values,
    )


def organization_accounts():
    if not ORGANIZATION_TARGET_IDS:
        raise ValueError("At least one organization root or OU ID is required")
    organizations = boto3.client("organizations", config=SDK_CONFIG)
    accounts = {}
    visited = set()

    def visit(parent_id):
        if parent_id in visited:
            return
        visited.add(parent_id)
        for account in paginate(
            organizations, "list_accounts_for_parent", "Accounts", ParentId=parent_id
        ):
            state = account.get("State") or account.get("Status")
            if state == "ACTIVE" and account.get("Id") not in EXCLUDED_ACCOUNT_IDS:
                accounts[account["Id"]] = {
                    "accountId": account["Id"],
                    "accountName": account.get("Name") or account["Id"],
                }
        for unit in paginate(
            organizations,
            "list_organizational_units_for_parent",
            "OrganizationalUnits",
            ParentId=parent_id,
        ):
            visit(unit["Id"])

    for target_id in ORGANIZATION_TARGET_IDS:
        visit(target_id)
    return sorted(accounts.values(), key=lambda item: item["accountId"])


def discovery_handler(event, context):
    del context
    run_id = str(uuid.uuid4())
    started_at = isoformat()
    accounts = organization_accounts()
    if not accounts:
        raise RuntimeError("Organization discovery returned no active accounts")
    target_key = f"runs/{run_id}/targets.json"
    put_json(
        target_key,
        accounts,
        metadata={"run-id": run_id, "evidence-type": "collection-targets"},
    )
    expires_at = int(utc_now().timestamp()) + (400 * 24 * 60 * 60)
    with table().batch_writer() as batch:
        batch.put_item(
            Item={
                "runKey": run_key(run_id),
                "targetKey": "RUN",
                "runId": run_id,
                "status": "running",
                "startedAt": started_at,
                "trigger": str((event or {}).get("trigger", "schedule"))[:80],
                "accountCount": len(accounts),
                "regionAllowList": sorted(REGION_ALLOW_LIST),
                "expiresAt": expires_at,
            }
        )
        for account in accounts:
            batch.put_item(
                Item={
                    "runKey": run_key(run_id),
                    "targetKey": f"ACCOUNT#{account['accountId']}",
                    **account,
                    "status": "pending",
                    "startedAt": "",
                    "completedAt": "",
                    "regionsExpected": 0,
                    "regionsSucceeded": 0,
                    "regionsFailed": 0,
                    "expiresAt": expires_at,
                }
            )
    return {
        "schemaVersion": "2.0",
        "runId": run_id,
        "startedAt": started_at,
        "accountCount": len(accounts),
        "targetsBucket": EVIDENCE_BUCKET,
        "targetsKey": target_key,
    }


def credentials_for(account_id):
    if not ACCOUNT_ID_PATTERN.fullmatch(account_id or ""):
        raise ValueError("Invalid AWS account ID")
    if account_id == SOURCE_ACCOUNT_ID:
        return None
    result = boto3.client("sts", config=SDK_CONFIG).assume_role(
        RoleArn=f"arn:{PARTITION}:iam::{account_id}:role/{MEMBER_ROLE_NAME}",
        RoleSessionName=f"gatewatch-{account_id}",
        DurationSeconds=3600,
    )
    credentials = result["Credentials"]
    return {
        "aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretAccessKey"],
        "aws_session_token": credentials["SessionToken"],
    }


def client(service, region, credentials):
    return boto3.client(service, region_name=region, config=SDK_CONFIG, **(credentials or {}))


def enabled_regions(credentials):
    ec2 = client("ec2", SOURCE_REGION, credentials)
    values = {
        item["RegionName"]
        for item in ec2.describe_regions(AllRegions=True).get("Regions", [])
        if item.get("OptInStatus") in {"opt-in-not-required", "opted-in"}
    }
    return sorted(values & REGION_ALLOW_LIST if REGION_ALLOW_LIST else values)


def instance_details(ec2, interfaces):
    instance_ids = sorted(
        {
            item.get("Attachment", {}).get("InstanceId")
            for item in interfaces
            if item.get("Attachment", {}).get("InstanceId")
        }
    )
    result = {}
    for start in range(0, len(instance_ids), 100):
        response = ec2.describe_instances(InstanceIds=instance_ids[start : start + 100])
        for reservation in response.get("Reservations", []):
            for item in reservation.get("Instances", []):
                tags = tags_to_dict(item.get("Tags"))
                result[item["InstanceId"]] = {
                    "name": tags.get("Name") or item["InstanceId"],
                    "arn": None,
                    "tags": tags,
                }
    return result


def resource_type(interface):
    description = str(interface.get("Description", "")).lower()
    interface_type = str(interface.get("InterfaceType", "network_interface")).lower()
    if interface.get("Attachment", {}).get("InstanceId"):
        return "AWS::EC2::Instance"
    if "rds" in description:
        return "AWS::RDS::DBInstance"
    if "elb" in description or "load balancer" in description:
        return "AWS::ElasticLoadBalancingV2::LoadBalancer"
    if "lambda" in description or interface_type == "lambda":
        return "AWS::Lambda::Function"
    if "efs" in description:
        return "AWS::EFS::FileSystem"
    return f"AWS::EC2::{interface_type.replace('_', ' ').title().replace(' ', '')}"


def broad_nacl_ingress(nacls_by_subnet, subnet_id):
    entries = nacls_by_subnet.get(subnet_id, [])
    return any(
        not entry.get("Egress", False)
        and entry.get("RuleAction") == "allow"
        and entry.get("RuleNumber", 32767) < 32767
        and (entry.get("CidrBlock") == "0.0.0.0/0" or entry.get("Ipv6CidrBlock") == "::/0")
        for entry in entries
    )


def scan_region(account, region, credentials, observed_at):
    if not REGION_PATTERN.fullmatch(region or ""):
        raise ValueError("Invalid AWS Region")
    ec2 = client("ec2", region, credentials)
    groups = list(paginate(ec2, "describe_security_groups", "SecurityGroups"))
    rules = list(paginate(ec2, "describe_security_group_rules", "SecurityGroupRules"))
    interfaces = list(paginate(ec2, "describe_network_interfaces", "NetworkInterfaces"))
    route_tables = list(paginate(ec2, "describe_route_tables", "RouteTables"))
    subnets = list(paginate(ec2, "describe_subnets", "Subnets"))
    network_acls = list(paginate(ec2, "describe_network_acls", "NetworkAcls"))
    internet_gateways = list(paginate(ec2, "describe_internet_gateways", "InternetGateways"))

    instances = instance_details(ec2, interfaces)
    rules_by_group = defaultdict(list)
    interfaces_by_group = defaultdict(list)
    for rule in rules:
        rules_by_group[rule.get("GroupId")].append(rule)
    for interface in interfaces:
        for group in interface.get("Groups", []):
            interfaces_by_group[group.get("GroupId")].append(interface)

    subnet_by_id = {item["SubnetId"]: item for item in subnets}
    main_routes = {}
    explicit_routes = {}
    for route_table in route_tables:
        for association in route_table.get("Associations", []):
            if association.get("SubnetId"):
                explicit_routes[association["SubnetId"]] = route_table
            elif association.get("Main"):
                main_routes[route_table.get("VpcId")] = route_table
    igw_ids = {
        gateway["InternetGatewayId"]
        for gateway in internet_gateways
        if any(attachment.get("State") == "available" for attachment in gateway.get("Attachments", []))
    }
    nacls_by_subnet = {}
    for network_acl in network_acls:
        for association in network_acl.get("Associations", []):
            if association.get("SubnetId"):
                nacls_by_subnet[association["SubnetId"]] = network_acl.get("Entries", [])

    normalized_groups = []
    for group in groups:
        group_id = group["GroupId"]
        group_rules = sorted(rules_by_group[group_id], key=lambda item: item.get("SecurityGroupRuleId", ""))
        group_interfaces = interfaces_by_group[group_id]
        attachments = []
        subnet_ids = sorted({item.get("SubnetId") for item in group_interfaces if item.get("SubnetId")})
        route_ids = set()
        has_ipv4_igw_route = False
        has_ipv6_igw_route = False
        direct_ipv4_path_count = 0
        direct_ipv6_path_count = 0
        for interface in group_interfaces:
            instance_id = interface.get("Attachment", {}).get("InstanceId")
            instance = instances.get(instance_id, {})
            interface_tags = tags_to_dict(interface.get("TagSet"))
            attachments.append(
                {
                    "resourceId": instance_id or interface["NetworkInterfaceId"],
                    "resourceName": instance.get("name") or interface_tags.get("Name") or interface["NetworkInterfaceId"],
                    "resourceType": resource_type(interface),
                    "resourceArn": instance.get("arn"),
                    "networkInterfaceId": interface["NetworkInterfaceId"],
                    "description": str(interface.get("Description", ""))[:500],
                    "privateIpAddress": interface.get("PrivateIpAddress"),
                    "publicIpAddress": interface.get("Association", {}).get("PublicIp"),
                    "subnetId": interface.get("SubnetId"),
                    "vpcId": interface.get("VpcId"),
                    "tags": {**interface_tags, **instance.get("tags", {})},
                }
            )
        for subnet_id in subnet_ids:
            subnet = subnet_by_id.get(subnet_id, {})
            route_table = explicit_routes.get(subnet_id) or main_routes.get(subnet.get("VpcId"))
            if not route_table:
                continue
            route_ids.add(route_table["RouteTableId"])
            subnet_has_ipv4_igw_route = any(
                route.get("State") == "active"
                and route.get("GatewayId") in igw_ids
                and route.get("DestinationCidrBlock") == "0.0.0.0/0"
                for route in route_table.get("Routes", [])
            )
            subnet_has_ipv6_igw_route = any(
                route.get("State") == "active"
                and route.get("GatewayId") in igw_ids
                and route.get("DestinationIpv6CidrBlock") == "::/0"
                for route in route_table.get("Routes", [])
            )
            subnet_nacl_allows = broad_nacl_ingress(nacls_by_subnet, subnet_id)
            has_ipv4_igw_route = has_ipv4_igw_route or subnet_has_ipv4_igw_route
            has_ipv6_igw_route = has_ipv6_igw_route or subnet_has_ipv6_igw_route
            direct_ipv4_path_count += sum(
                1 for item in group_interfaces
                if item.get("SubnetId") == subnet_id
                and (item.get("Association") or {}).get("PublicIp")
                and subnet_has_ipv4_igw_route
                and subnet_nacl_allows
            )
            direct_ipv6_path_count += sum(
                1 for item in group_interfaces
                if item.get("SubnetId") == subnet_id
                and item.get("Ipv6Addresses")
                and subnet_has_ipv6_igw_route
                and subnet_nacl_allows
            )

        public_ingress = sum(
            1 for rule in group_rules
            if not rule.get("IsEgress") and (rule.get("CidrIpv4") == "0.0.0.0/0" or rule.get("CidrIpv6") == "::/0")
        )
        public_egress = sum(
            1 for rule in group_rules
            if rule.get("IsEgress") and (rule.get("CidrIpv4") == "0.0.0.0/0" or rule.get("CidrIpv6") == "::/0")
        )
        normalized_groups.append(
            {
                "accountId": account["accountId"],
                "accountName": account["accountName"],
                "region": region,
                "id": group_id,
                "name": group.get("GroupName"),
                "description": group.get("Description"),
                "vpcId": group.get("VpcId"),
                "isDefault": group.get("GroupName") == "default",
                "tags": tags_to_dict(group.get("Tags")),
                "inboundRuleCount": sum(1 for rule in group_rules if not rule.get("IsEgress")),
                "outboundRuleCount": sum(1 for rule in group_rules if rule.get("IsEgress")),
                "publicIngressRuleCount": public_ingress,
                "publicEgressRuleCount": public_egress,
                "networkInterfaceAttachmentCount": len(group_interfaces),
                "networkInterfaceTypes": dict(
                    sorted(
                        {
                            item.get("InterfaceType", "network_interface"): sum(
                                1 for candidate in group_interfaces
                                if candidate.get("InterfaceType", "network_interface") == item.get("InterfaceType", "network_interface")
                            )
                            for item in group_interfaces
                        }.items()
                    )
                ),
                "resourceAttachments": attachments,
                "networkEvidence": {
                    "evidenceVersion": 2,
                    "subnetIds": subnet_ids,
                    "routeTableIds": sorted(route_ids),
                    "networkAclIds": sorted(
                        {
                            association.get("NetworkAclId") or network_acl.get("NetworkAclId")
                            for network_acl in network_acls
                            for association in network_acl.get("Associations", [])
                            if association.get("SubnetId") in subnet_ids
                        } - {None}
                    ),
                    "publicAddressCount": sum(1 for item in attachments if item.get("publicIpAddress")),
                    "publicIpv6AddressCount": sum(
                        len(item.get("Ipv6Addresses", [])) for item in group_interfaces
                    ),
                    "directIpv4InternetPathCount": direct_ipv4_path_count,
                    "directIpv6InternetPathCount": direct_ipv6_path_count,
                    "internetGatewayRoute": has_ipv4_igw_route or has_ipv6_igw_route,
                    "ipv4InternetGatewayRoute": has_ipv4_igw_route,
                    "ipv6InternetGatewayRoute": has_ipv6_igw_route,
                    "networkAclAllowsInternetIngress": any(broad_nacl_ingress(nacls_by_subnet, subnet_id) for subnet_id in subnet_ids),
                    "state": (
                        "configured-internet-path"
                        if (
                            direct_ipv4_path_count > 0
                        ) or (direct_ipv6_path_count > 0)
                        else "blocked"
                        if subnet_ids and route_ids and any(
                            subnet_id in nacls_by_subnet for subnet_id in subnet_ids
                        )
                        else "incomplete"
                    ),
                },
                "observedAt": observed_at,
                "rules": [
                    {
                        "ruleId": rule.get("SecurityGroupRuleId"),
                        "isEgress": bool(rule.get("IsEgress")),
                        "protocol": str(rule.get("IpProtocol", "-1")),
                        "fromPort": rule.get("FromPort"),
                        "toPort": rule.get("ToPort"),
                        "cidrIpv4": rule.get("CidrIpv4"),
                        "cidrIpv6": rule.get("CidrIpv6"),
                        "prefixListId": rule.get("PrefixListId"),
                        "referencedGroup": rule.get("ReferencedGroupInfo"),
                        "description": rule.get("Description"),
                    }
                    for rule in group_rules
                ],
            }
        )

    return {
        "schemaVersion": "2.0",
        "evidenceType": "security-group-inventory-shard",
        "runId": None,
        "observedAt": observed_at,
        "target": {
            "targetId": f"{account['accountId']}:{region}",
            "accountId": account["accountId"],
            "accountName": account["accountName"],
            "region": region,
        },
        "coverage": {
            "securityGroupCount": len(normalized_groups),
            "securityGroupRuleCount": len(rules),
            "networkInterfaceCount": len(interfaces),
            "routeTableCount": len(route_tables),
            "subnetCount": len(subnets),
            "networkAclCount": len(network_acls),
            "internetGatewayCount": len(internet_gateways),
        },
        "securityGroups": normalized_groups,
    }


def collect_region(run_id, account, region, credentials, observed_at):
    target_key = f"TARGET#{account['accountId']}#{region}"
    started_at = isoformat()
    update_item(
        run_id,
        target_key,
        {
            "accountId": account["accountId"],
            "accountName": account["accountName"],
            "region": region,
            "status": "running",
            "startedAt": started_at,
            "completedAt": "",
        },
    )
    try:
        shard = scan_region(account, region, credentials, observed_at)
        shard["runId"] = run_id
        key = f"runs/{run_id}/shards/account={account['accountId']}/region={region}/inventory.json.gz"
        stored = put_json(
            key,
            shard,
            compress=True,
            metadata={
                "run-id": run_id,
                "account-id": account["accountId"],
                "region": region,
                "evidence-type": "security-group-inventory-shard",
            },
        )
        completed_at = isoformat()
        update_item(
            run_id,
            target_key,
            {
                "status": "succeeded",
                "completedAt": completed_at,
                "objectKey": stored["key"],
                "checksumSha256": stored["sha256"],
                "objectBytes": stored["bytes"],
                **shard["coverage"],
            },
        )
        return {"region": region, "status": "succeeded", **shard["coverage"]}
    except (BotoCoreError, ClientError, ValueError, RuntimeError) as error:
        failure = clean_error(error)
        completed_at = isoformat()
        error_key = f"runs/{run_id}/errors/account={account['accountId']}/region={region}.json"
        put_json(
            error_key,
            {
                "schemaVersion": "2.0",
                "evidenceType": "collection-error",
                "runId": run_id,
                "target": {**account, "region": region},
                "failedAt": completed_at,
                "error": failure,
            },
            metadata={"run-id": run_id, "account-id": account["accountId"], "region": region},
        )
        update_item(
            run_id,
            target_key,
            {
                "status": "failed",
                "completedAt": completed_at,
                "errorCode": failure["code"],
                "errorMessage": failure["message"],
                "errorObjectKey": error_key,
            },
        )
        LOGGER.warning(json.dumps({"message": "Region collection failed", "runId": run_id, "accountId": account["accountId"], "region": region, "errorCode": failure["code"]}))
        return {"region": region, "status": "failed", "errorCode": failure["code"]}


def worker_handler(event, context):
    del context
    run_id = str((event or {}).get("runId", ""))
    run_key(run_id)
    raw_account = (event or {}).get("account") or {}
    account = {
        "accountId": str(raw_account.get("accountId", "")),
        "accountName": str(raw_account.get("accountName", ""))[:160],
    }
    if not ACCOUNT_ID_PATTERN.fullmatch(account["accountId"]):
        raise ValueError("Invalid account target")
    account_key = f"ACCOUNT#{account['accountId']}"
    started_at = isoformat()
    update_item(run_id, account_key, {"status": "running", "startedAt": started_at})
    try:
        credentials = credentials_for(account["accountId"])
        regions = enabled_regions(credentials)
        if not regions:
            raise RuntimeError("No enabled Regions matched the collection policy")
        observed_at = isoformat()
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_REGION_CONCURRENCY) as executor:
            results = list(
                executor.map(
                    lambda region: collect_region(run_id, account, region, credentials, observed_at),
                    regions,
                )
            )
        succeeded = sum(1 for item in results if item["status"] == "succeeded")
        failed = len(results) - succeeded
        status = "succeeded" if failed == 0 else "partial" if succeeded else "failed"
        update_item(
            run_id,
            account_key,
            {
                "status": status,
                "completedAt": isoformat(),
                "regionsExpected": len(regions),
                "regionsSucceeded": succeeded,
                "regionsFailed": failed,
            },
        )
        return {"accountId": account["accountId"], "status": status, "regions": len(regions)}
    except (BotoCoreError, ClientError, ValueError, RuntimeError) as error:
        failure = clean_error(error)
        update_item(
            run_id,
            account_key,
            {
                "status": "failed",
                "completedAt": isoformat(),
                "regionsExpected": 0,
                "regionsSucceeded": 0,
                "regionsFailed": 0,
                "errorCode": failure["code"],
                "errorMessage": failure["message"],
            },
        )
        LOGGER.warning(json.dumps({"message": "Account collection failed", "runId": run_id, "accountId": account["accountId"], "errorCode": failure["code"]}))
        return {"accountId": account["accountId"], "status": "failed", "errorCode": failure["code"]}


def query_run(run_id):
    items = []
    request = {"KeyConditionExpression": Key("runKey").eq(run_key(run_id))}
    while True:
        response = table().query(**request)
        items.extend(response.get("Items", []))
        if not response.get("LastEvaluatedKey"):
            break
        request["ExclusiveStartKey"] = response["LastEvaluatedKey"]
    return items


def finalizer_handler(event, context):
    del context
    run_id = str((event or {}).get("runId", ""))
    items = query_run(run_id)
    run = next((item for item in items if item["targetKey"] == "RUN"), None)
    if not run:
        raise RuntimeError("Collection run state was not found")
    accounts = [item for item in items if item["targetKey"].startswith("ACCOUNT#")]
    targets = [item for item in items if item["targetKey"].startswith("TARGET#")]
    succeeded_targets = [item for item in targets if item.get("status") == "succeeded"]
    failed_targets = [item for item in targets if item.get("status") == "failed"]
    incomplete_targets = [
        item for item in targets
        if item.get("status") not in {"succeeded", "failed"}
    ]
    account_success = sum(1 for item in accounts if item.get("status") == "succeeded")
    account_partial = sum(1 for item in accounts if item.get("status") == "partial")
    account_failed = sum(1 for item in accounts if item.get("status") == "failed")
    account_incomplete = len(accounts) - account_success - account_partial - account_failed
    complete = (
        len(accounts) > 0
        and account_success == len(accounts)
        and not failed_targets
    )
    completed_at = isoformat()
    status = (
        "succeeded"
        if complete
        else "partial"
        if succeeded_targets or account_success or account_partial
        else "failed"
    )
    summary = {
        "accountsExpected": len(accounts),
        "accountsSucceeded": account_success,
        "accountsPartial": account_partial,
        "accountsFailed": account_failed,
        "accountsIncomplete": account_incomplete,
        "regionsExpected": len(targets),
        "regionsSucceeded": len(succeeded_targets),
        "regionsFailed": len(failed_targets),
        "regionsIncomplete": len(incomplete_targets),
        "securityGroupCount": sum(int(item.get("securityGroupCount", 0)) for item in succeeded_targets),
        "securityGroupRuleCount": sum(int(item.get("securityGroupRuleCount", 0)) for item in succeeded_targets),
        "networkInterfaceCount": sum(int(item.get("networkInterfaceCount", 0)) for item in succeeded_targets),
    }
    coverage = round(
        100
        * (
            (account_success + (account_partial * 0.5)) / max(1, len(accounts))
            + len(succeeded_targets) / max(1, len(targets))
        )
        / 2
    )
    manifest = {
        "schemaVersion": "2.0",
        "evidenceType": "organization-collection-manifest",
        "runId": run_id,
        "status": status,
        "complete": complete,
        "startedAt": run.get("startedAt"),
        "completedAt": completed_at,
        "coveragePercent": coverage,
        "summary": summary,
        "accounts": [
            {
                **{
                    key: item.get(key, "")
                    for key in (
                        "accountId", "accountName", "regionsExpected",
                        "regionsSucceeded", "regionsFailed", "errorCode", "completedAt"
                    )
                },
                "status": item.get("status")
                if item.get("status") in {"succeeded", "partial", "failed"}
                else "incomplete",
            }
            for item in sorted(accounts, key=lambda value: value.get("accountId", ""))
        ],
        "targets": [
            {
                **{
                    key: item.get(key, "")
                    for key in (
                        "accountId", "accountName", "region", "completedAt",
                        "objectKey", "checksumSha256", "securityGroupCount",
                        "securityGroupRuleCount", "networkInterfaceCount", "errorCode"
                    )
                },
                "status": item.get("status")
                if item.get("status") in {"succeeded", "failed"}
                else "incomplete",
            }
            for item in sorted(targets, key=lambda value: (value.get("accountId", ""), value.get("region", "")))
        ],
    }
    immutable = put_json(
        f"runs/{run_id}/manifest.json",
        manifest,
        metadata={"run-id": run_id, "evidence-type": "organization-collection-manifest"},
    )
    put_json(
        "manifests/latest.json",
        manifest,
        metadata={"run-id": run_id, "immutable-manifest-sha256": immutable["sha256"]},
    )
    update_item(
        run_id,
        "RUN",
        {
            "status": status,
            "completedAt": completed_at,
            "coveragePercent": coverage,
            "manifestKey": immutable["key"],
            "manifestChecksumSha256": immutable["sha256"],
            **summary,
        },
    )
    LOGGER.info(json.dumps({"message": "Organization collection finalized", "runId": run_id, "status": status, "coveragePercent": coverage, **summary}))
    return {"runId": run_id, "status": status, "coveragePercent": coverage, "manifestKey": immutable["key"], "summary": summary}
