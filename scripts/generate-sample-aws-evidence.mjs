import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";

const outputDirectory = resolve(process.argv[2] ?? "samples/aws-evidence-batch");
const accountId = "428196730552";
const region = "us-east-1";
const appGroupId = "sg-0a41f2e91b71";
const edgeGroupId = "sg-0d3c99118aae";
const appEniId = "eni-0a41f2e91b71";
const appInstanceId = "i-02aa9e6f3";
const albId = "app/prod-payments-alb/50dc6c495c0c9188";
const webAclArn = `arn:aws:wafv2:${region}:${accountId}:regional/webacl/payments-edge/11111111-2222-3333-4444-555555555555`;
const apiId = "a1b2c3d4e5";
const files = [];

mkdirSync(outputDirectory, { recursive: true });

function save(name, sourceType, content, notes) {
  const body = Buffer.isBuffer(content) ? content : Buffer.from(content);
  writeFileSync(resolve(outputDirectory, name), body, { mode: 0o644 });
  files.push({
    name,
    sourceType,
    bytes: body.length,
    sha256: createHash("sha256").update(body).digest("hex"),
    notes,
  });
}

function json(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function relationship(resourceType, resourceId, name = "Is associated with SecurityGroup") {
  return { resourceType, resourceId, name };
}

function configItem({ resourceType, resourceId, stateId, captureTime, configuration = {}, relationships = [], arn = "" }) {
  return {
    relatedEvents: [],
    relationships,
    configuration,
    supplementaryConfiguration: {},
    tags: { Environment: "Production", Synthetic: "true" },
    configurationItemVersion: "1.3",
    configurationItemCaptureTime: captureTime,
    configurationStateId: stateId,
    awsAccountId: accountId,
    configurationItemStatus: "OK",
    resourceType,
    resourceId,
    resourceName: resourceId,
    ARN: arn,
    awsRegion: region,
    availabilityZone: "us-east-1a",
    configurationStateMd5Hash: "",
    resourceCreationTime: "2025-01-15T10:00:00.000Z",
  };
}

const appGroupCurrent = configItem({
  resourceType: "AWS::EC2::SecurityGroup",
  resourceId: appGroupId,
  stateId: "1700000000001",
  captureTime: "2026-08-07T12:10:30.000Z",
  arn: `arn:aws:ec2:${region}:${accountId}:security-group/${appGroupId}`,
  configuration: {
    groupName: "prod-payments-api",
    groupId: appGroupId,
    description: "Synthetic payments API security group",
    vpcId: "vpc-prod-core",
    ipPermissions: [
      {
        ipProtocol: "tcp",
        fromPort: 22,
        toPort: 22,
        ipRanges: [{ cidrIp: "0.0.0.0/0", description: "Synthetic risky rule" }],
        ipv6Ranges: [],
        userIdGroupPairs: [],
        prefixListIds: [],
      },
      {
        ipProtocol: "tcp",
        fromPort: 8443,
        toPort: 8443,
        ipRanges: [],
        ipv6Ranges: [],
        userIdGroupPairs: [{ groupId: edgeGroupId, userId: accountId, description: "ALB to API" }],
        prefixListIds: [],
      },
    ],
    ipPermissionsEgress: [
      { ipProtocol: "-1", ipRanges: [{ cidrIp: "0.0.0.0/0" }], ipv6Ranges: [], userIdGroupPairs: [], prefixListIds: [] },
    ],
  },
});

const edgeGroupCurrent = configItem({
  resourceType: "AWS::EC2::SecurityGroup",
  resourceId: edgeGroupId,
  stateId: "1700000000002",
  captureTime: "2026-08-07T12:10:31.000Z",
  arn: `arn:aws:ec2:${region}:${accountId}:security-group/${edgeGroupId}`,
  configuration: {
    groupName: "prod-public-alb",
    groupId: edgeGroupId,
    description: "Synthetic public ALB security group",
    vpcId: "vpc-prod-core",
    ipPermissions: [
      { ipProtocol: "tcp", fromPort: 443, toPort: 443, ipRanges: [{ cidrIp: "0.0.0.0/0" }], ipv6Ranges: [{ cidrIpv6: "::/0" }], userIdGroupPairs: [], prefixListIds: [] },
    ],
    ipPermissionsEgress: [
      { ipProtocol: "tcp", fromPort: 8443, toPort: 8443, ipRanges: [], ipv6Ranges: [], userIdGroupPairs: [{ groupId: appGroupId, userId: accountId }], prefixListIds: [] },
    ],
  },
});

const snapshotItems = [
  appGroupCurrent,
  edgeGroupCurrent,
  configItem({
    resourceType: "AWS::EC2::NetworkInterface",
    resourceId: appEniId,
    stateId: "1700000000003",
    captureTime: "2026-08-07T12:10:32.000Z",
    configuration: { networkInterfaceId: appEniId, privateIpAddress: "10.20.1.10", vpcId: "vpc-prod-core", subnetId: "subnet-payments-a" },
    relationships: [relationship("AWS::EC2::SecurityGroup", appGroupId)],
  }),
  configItem({
    resourceType: "AWS::EC2::Instance",
    resourceId: appInstanceId,
    stateId: "1700000000004",
    captureTime: "2026-08-07T12:10:33.000Z",
    configuration: { instanceId: appInstanceId, privateIpAddress: "10.20.1.10", state: { name: "running" }, vpcId: "vpc-prod-core" },
    relationships: [relationship("AWS::EC2::SecurityGroup", appGroupId)],
  }),
  configItem({
    resourceType: "AWS::ElasticLoadBalancingV2::LoadBalancer",
    resourceId: albId,
    stateId: "1700000000005",
    captureTime: "2026-08-07T12:10:34.000Z",
    configuration: { scheme: "internet-facing", type: "application", dnsName: "dualstack.payments.example.com" },
    relationships: [relationship("AWS::EC2::SecurityGroup", edgeGroupId)],
  }),
  configItem({
    resourceType: "AWS::WAFv2::WebACL",
    resourceId: webAclArn,
    stateId: "1700000000006",
    captureTime: "2026-08-07T12:10:35.000Z",
    configuration: { name: "payments-edge", scope: "REGIONAL", defaultAction: { allow: {} } },
    relationships: [relationship("AWS::EC2::SecurityGroup", edgeGroupId, "Protects an ALB associated with SecurityGroup")],
  }),
  configItem({
    resourceType: "AWS::ApiGatewayV2::Api",
    resourceId: apiId,
    stateId: "1700000000007",
    captureTime: "2026-08-07T12:10:36.000Z",
    configuration: { name: "payments-private-api", protocolType: "HTTP" },
    relationships: [relationship("AWS::EC2::SecurityGroup", appGroupId, "Uses a VPC link associated with SecurityGroup")],
  }),
];

save(
  "01-config-snapshot.json",
  "config-snapshot",
  json({ fileVersion: "1.0", configurationItems: snapshotItems }),
  "Current security groups and resource relationships used to correlate the other files.",
);

const previousAppGroup = configItem({
  resourceType: "AWS::EC2::SecurityGroup",
  resourceId: appGroupId,
  stateId: "1699999999001",
  captureTime: "2026-08-07T11:45:00.000Z",
  arn: `arn:aws:ec2:${region}:${accountId}:security-group/${appGroupId}`,
  configuration: {
    groupName: "prod-payments-api",
    groupId: appGroupId,
    description: "Synthetic payments API security group",
    vpcId: "vpc-prod-core",
    ipPermissions: [
      { ipProtocol: "tcp", fromPort: 22, toPort: 22, ipRanges: [{ cidrIp: "10.8.0.0/16", description: "Managed operations" }], ipv6Ranges: [], userIdGroupPairs: [], prefixListIds: [] },
    ],
    ipPermissionsEgress: [
      { ipProtocol: "-1", ipRanges: [{ cidrIp: "0.0.0.0/0" }], ipv6Ranges: [], userIdGroupPairs: [], prefixListIds: [] },
    ],
  },
});

save(
  "02-config-history.json",
  "config-history",
  json([appGroupCurrent, previousAppGroup]),
  "Contains the same current item as the snapshot plus the preceding state; one cross-file duplicate is intentional.",
);

const cloudTrailChange = {
  eventVersion: "1.09",
  userIdentity: {
    type: "AssumedRole",
    principalId: "AROASYNTHETIC:terraform-payments",
    arn: `arn:aws:sts::${accountId}:assumed-role/terraform-ci/payments-deploy-4812`,
    accountId,
    sessionContext: { sessionIssuer: { type: "Role", arn: `arn:aws:iam::${accountId}:role/terraform-ci`, userName: "terraform-ci" }, attributes: { mfaAuthenticated: "false", creationDate: "2026-08-07T12:00:00Z" } },
  },
  eventTime: "2026-08-07T12:10:00Z",
  eventSource: "ec2.amazonaws.com",
  eventName: "AuthorizeSecurityGroupIngress",
  awsRegion: region,
  sourceIPAddress: "10.8.14.22",
  userAgent: "APN/1.0 HashiCorp/1.0 Terraform/1.9",
  requestParameters: {
    groupId: appGroupId,
    ipPermissions: { items: [{ ipProtocol: "tcp", fromPort: 22, toPort: 22, ipRanges: { items: [{ cidrIp: "0.0.0.0/0", description: "Synthetic risky rule" }] } }] },
  },
  responseElements: { requestId: "11111111-1111-4111-8111-111111111111", _return: true },
  requestID: "11111111-1111-4111-8111-111111111111",
  eventID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  readOnly: false,
  eventType: "AwsApiCall",
  managementEvent: true,
  recipientAccountId: accountId,
  eventCategory: "Management",
};
const cloudTrailRecords = [
  cloudTrailChange,
  cloudTrailChange,
  {
    ...cloudTrailChange,
    eventTime: "2026-08-07T12:12:00Z",
    eventName: "RevokeSecurityGroupEgress",
    eventID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    requestID: "22222222-2222-4222-8222-222222222222",
    requestParameters: { groupId: appGroupId, ipPermissions: { items: [{ ipProtocol: "-1", ipRanges: { items: [{ cidrIp: "0.0.0.0/0" }] } }] } },
    responseElements: null,
    errorCode: "Client.UnauthorizedOperation",
    errorMessage: "Synthetic denied request retained as evidence but not treated as a successful state change.",
  },
  {
    ...cloudTrailChange,
    eventTime: "2026-08-07T12:13:00Z",
    eventName: "DescribeInstances",
    eventID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    requestID: "33333333-3333-4333-8333-333333333333",
    requestParameters: {},
    responseElements: null,
    readOnly: true,
  },
];
save(
  "03-cloudtrail.json.gz",
  "cloudtrail",
  gzipSync(Buffer.from(json({ Records: cloudTrailRecords })), { level: 9 }),
  "One successful ingress change, an exact duplicate, one failed request, and one unrelated management event.",
);

save(
  "04-vpc-flow.log",
  "vpc-flow-logs",
  [
    "2 428196730552 eni-0a41f2e91b71 198.51.100.27 10.20.1.10 54122 22 6 4 320 1786095010 1786095070 ACCEPT OK",
    "2 428196730552 eni-0a41f2e91b71 203.0.113.88 10.20.1.10 61244 22 6 3 240 1786095070 1786095130 ACCEPT OK",
    "2 428196730552 eni-0a41f2e91b71 192.0.2.90 10.20.1.10 49910 3389 6 2 160 1786095130 1786095190 REJECT OK",
    "",
  ].join("\n"),
  "Default-format accepted SSH traffic and a rejected RDP probe on the Config-related ENI.",
);

save(
  "05-reachability-analyzer.json",
  "reachability-analyzer",
  json({
    NetworkInsightsAnalyses: [{
      NetworkInsightsAnalysisId: "nia-0a41f2e91b71",
      NetworkInsightsAnalysisArn: `arn:aws:ec2:${region}:${accountId}:network-insights-analysis/nia-0a41f2e91b71`,
      NetworkInsightsPathId: "nip-0a41f2e91b71",
      StartDate: "2026-08-07T12:14:00.000Z",
      Status: "succeeded",
      NetworkPathFound: true,
      ForwardPathComponents: [
        { SequenceNumber: 1, Component: { Id: "igw-prod" }, InboundHeader: { Protocol: "6", SourceAddresses: ["0.0.0.0/0"], DestinationAddresses: ["10.20.1.10/32"], DestinationPortRanges: [{ From: 22, To: 22 }] } },
        { SequenceNumber: 2, Component: { Id: appEniId }, SecurityGroupRule: { GroupId: appGroupId, SecurityGroupRuleId: "sgr-8f29", Direction: "ingress", Protocol: "tcp", PortRange: { From: 22, To: 22 }, Cidr: "0.0.0.0/0" } },
      ],
      ReturnPathComponents: [],
    }],
  }),
  "A successful configuration-based path from the internet to SSH through the application security group.",
);

save(
  "06-network-access-analyzer.json",
  "network-access-analyzer",
  json({
    NetworkInsightsAccessScopeAnalysisId: "nisa-0a41f2e91b71",
    AnalysisStatus: "succeeded",
    AnalysisFindings: [{
      NetworkInsightsAccessScopeAnalysisId: "nisa-0a41f2e91b71",
      NetworkInsightsAccessScopeId: "nis-0a41f2e91b71",
      FindingId: "nisaa-0a41f2e91b71",
      FindingComponents: [
        { SequenceNumber: 1, Component: { Id: "igw-prod" } },
        { SequenceNumber: 2, Component: { Id: appEniId }, SecurityGroupRule: { GroupId: appGroupId, SecurityGroupRuleId: "sgr-8f29", Direction: "ingress", Protocol: "tcp", PortRange: { From: 22, To: 22 }, Cidr: "0.0.0.0/0" } },
      ],
    }],
  }),
  "A Network Access Scope finding for the same public administrative path.",
);

save(
  "07-elb-access.log",
  "elastic-load-balancing",
  `https 2026-08-07T12:15:00.186641Z ${albId} 198.51.100.40:54100 10.20.1.10:8443 0.001 0.004 0.001 200 200 512 2048 "POST https://payments.example.com:443/authorize HTTP/1.1" "Gatewatch-Synthetic-Client/1.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:428196730552:targetgroup/payments-api/73e2d6bc24d8a067 "Root=1-synthetic" "payments.example.com" "arn:aws:acm:us-east-1:428196730552:certificate/00000000-0000-0000-0000-000000000000" 1 2026-08-07T12:15:00.180000Z "forward" "-" "-" "10.20.1.10:8443" "200" "-" "-" TID_SYNTHETIC "-" "-" "-"\n`,
  "A standard ALB HTTPS request correlated to the edge security group through Config.",
);

const wafRecords = [
  { timestamp: 1786104961000, formatVersion: 1, webaclId: webAclArn, terminatingRuleId: "AWS-AWSManagedRulesCommonRuleSet", terminatingRuleType: "MANAGED_RULE_GROUP", action: "BLOCK", terminatingRuleMatchDetails: [{ conditionType: "SQL_INJECTION", sensitivityLevel: "HIGH", location: "QUERY_STRING", matchedData: ["OR", "1=1"] }], httpSourceName: "ALB", httpSourceId: albId, ruleGroupList: [], rateBasedRuleList: [], nonTerminatingMatchingRules: [], httpRequest: { clientIp: "203.0.113.99", country: "US", headers: [{ name: "host", value: "payments.example.com" }], uri: "/authorize", args: "account=1%20OR%201=1", httpVersion: "HTTP/1.1", httpMethod: "POST", requestId: "waf-synthetic-1" } },
  { timestamp: 1786104962000, formatVersion: 1, webaclId: webAclArn, terminatingRuleId: "Default_Action", terminatingRuleType: "REGULAR", action: "ALLOW", terminatingRuleMatchDetails: [], httpSourceName: "ALB", httpSourceId: albId, ruleGroupList: [], rateBasedRuleList: [], nonTerminatingMatchingRules: [], httpRequest: { clientIp: "198.51.100.40", country: "US", headers: [{ name: "host", value: "payments.example.com" }], uri: "/health", args: "", httpVersion: "HTTP/1.1", httpMethod: "GET", requestId: "waf-synthetic-2" } },
];
save("08-waf.jsonl", "waf", `${wafRecords.map(JSON.stringify).join("\n")}\n`, "One blocked SQL injection pattern and one allowed health check associated with the ALB Web ACL.");

save(
  "09-cloudfront.tsv",
  "cloudfront",
  [
    "#Version: 1.0",
    "#Fields: date time x-edge-location sc-bytes c-ip cs-method cs-host cs-uri-stem sc-status x-edge-request-id x-host-header cs-protocol",
    "2026-08-07\t12:16:10\tIAD89-C3\t2048\t198.51.100.40\tPOST\td111111abcdef8.cloudfront.net\t/authorize\t200\tcf-synthetic-1\tdualstack.payments.example.com\thttps",
    "2026-08-07\t12:16:11\tIAD89-C3\t512\t203.0.113.99\tGET\td111111abcdef8.cloudfront.net\t/admin\t403\tcf-synthetic-2\tdualstack.payments.example.com\thttps",
    "",
  ].join("\n"),
  "Legacy standard CloudFront TSV records whose origin hostname maps to the inventory ALB attachment.",
);

const apiGatewayRecords = [
  { requestId: "api-synthetic-1", extendedRequestId: "api-extended-1", ip: "198.51.100.40", requestTime: "07/Aug/2026:12:17:00 +0000", timestamp: "2026-08-07T12:17:00Z", httpMethod: "POST", routeKey: "POST /authorize", resourcePath: "/authorize", status: "200", protocol: "HTTP/1.1", responseLength: "384", apiId, accountId, region },
  { requestId: "api-synthetic-2", extendedRequestId: "api-extended-2", ip: "203.0.113.99", requestTime: "07/Aug/2026:12:17:01 +0000", timestamp: "2026-08-07T12:17:01Z", httpMethod: "POST", routeKey: "POST /authorize", resourcePath: "/authorize", status: "429", protocol: "HTTP/1.1", responseLength: "96", apiId, accountId, region },
];
save("10-api-gateway.jsonl", "api-gateway", `${apiGatewayRecords.map(JSON.stringify).join("\n")}\n`, "Structured API Gateway access logs for a successful request and a throttled request through a Config-related private API.");

const resolverRecords = [
  { version: "1.1", account_id: accountId, region, vpc_id: "vpc-prod-core", query_timestamp: "2026-08-07T12:18:00Z", query_name: "database.payments.internal.", query_type: "A", query_class: "IN", rcode: "NOERROR", answers: [{ Rdata: "10.20.2.15", Type: "A", Class: "IN" }], srcaddr: "10.20.1.10", srcport: "54211", transport: "UDP", srcids: { instance: appInstanceId } },
  { version: "1.1", account_id: accountId, region, vpc_id: "vpc-prod-core", query_timestamp: "2026-08-07T12:18:02Z", query_name: "synthetic-malware.example.", query_type: "A", query_class: "IN", rcode: "NOERROR", answers: [], firewall_rule_group_id: "rslvr-frg-synthetic", firewall_rule_action: "BLOCK", firewall_domain_list_id: "rslvr-fdl-synthetic", srcaddr: "10.20.1.10", srcport: "54212", transport: "UDP", srcids: { instance: appInstanceId } },
];
save("11-route53-resolver.jsonl", "route53-resolver", `${resolverRecords.map(JSON.stringify).join("\n")}\n`, "One normal internal lookup and one DNS Firewall-blocked domain from the attached application instance.");

const firewallRecords = [
  { firewall_name: "payments-egress", availability_zone: "us-east-1a", event_timestamp: "1786105140", event: { timestamp: "2026-08-07T12:19:00.006481+0000", flow_id: 1582438383425873, event_type: "alert", src_ip: "10.20.1.10", src_port: 55555, dest_ip: "192.0.2.16", dest_port: 443, proto: "TCP", alert: { action: "blocked", signature_id: 900001, rev: 1, signature: "Synthetic known-bad destination", category: "Potentially Bad Traffic", severity: 1 } } },
  { firewall_name: "payments-egress", availability_zone: "us-east-1a", event_timestamp: "1786105141", event: { timestamp: "2026-08-07T12:19:01.006481+0000", flow_id: 1582438383425874, event_type: "flow", src_ip: "10.20.1.10", src_port: 55556, dest_ip: "198.51.100.8", dest_port: 443, proto: "TCP", app_proto: "tls", flow: { pkts_toserver: 8, pkts_toclient: 7, bytes_toserver: 1460, bytes_toclient: 5200, start: "2026-08-07T12:18:55.000000+0000", end: "2026-08-07T12:19:01.000000+0000", age: 6, state: "closed", reason: "shutdown", alerted: false } } },
];
save("12-network-firewall.jsonl", "network-firewall", `${firewallRecords.map(JSON.stringify).join("\n")}\n`, "A blocked alert and an allowed TLS flow. These remain unmatched unless firewall-to-workload context is supplied.");

save(
  "13-guardduty.json",
  "guardduty",
  json({ findings: [{
    accountId,
    arn: `arn:aws:guardduty:${region}:${accountId}:detector/12abc34d567e8fa901bc2d34e56789f0/finding/guardduty-synthetic-1`,
    confidence: 92,
    createdAt: "2026-08-07T12:20:00.000Z",
    description: "The synthetic payments instance communicated with an IP address on a threat list.",
    id: "guardduty-synthetic-1",
    partition: "aws",
    region,
    resource: { instanceDetails: { availabilityZone: "us-east-1a", instanceId: appInstanceId, instanceState: "running", instanceType: "m6i.large", launchTime: "2026-08-01T08:00:00.000Z", networkInterfaces: [{ networkInterfaceId: appEniId, privateDnsName: "ip-10-20-1-10.ec2.internal", privateIpAddress: "10.20.1.10", privateIpAddresses: [{ privateDnsName: "ip-10-20-1-10.ec2.internal", privateIpAddress: "10.20.1.10" }], publicDnsName: "", publicIp: "", securityGroups: [{ groupId: appGroupId, groupName: "prod-payments-api" }], subnetId: "subnet-payments-a", vpcId: "vpc-prod-core" }], tags: [{ key: "Service", value: "Payments API" }] }, resourceType: "Instance" },
    schemaVersion: "2.0",
    service: { action: { actionType: "NETWORK_CONNECTION", networkConnectionAction: { blocked: false, connectionDirection: "OUTBOUND", localIpDetails: { ipAddressV4: "10.20.1.10" }, localPortDetails: { port: 49152, portName: "Unknown" }, protocol: "TCP", remoteIpDetails: { country: { countryName: "Example" }, ipAddressV4: "192.0.2.44", organization: { asn: "64500", asnOrg: "Synthetic Network", isp: "Synthetic ISP", org: "Synthetic Network" } }, remotePortDetails: { port: 443, portName: "HTTPS" } } }, archived: false, count: 1, detectorId: "12abc34d567e8fa901bc2d34e56789f0", eventFirstSeen: "2026-08-07T12:19:30.000Z", eventLastSeen: "2026-08-07T12:19:55.000Z", resourceRole: "ACTOR", serviceName: "guardduty" },
    severity: 8,
    title: "Synthetic EC2 instance communicated with a threat-list address",
    type: "Backdoor:EC2/C&CActivity.B!DNS",
    updatedAt: "2026-08-07T12:20:30.000Z",
  }] }),
  "A GuardDuty instance finding with a nested network interface and security-group association.",
);

save(
  "14-security-hub.json",
  "security-hub",
  json({ Findings: [{
    SchemaVersion: "2018-10-08",
    Id: `arn:aws:securityhub:${region}:${accountId}:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.19/finding/securityhub-synthetic-1`,
    ProductArn: `arn:aws:securityhub:${region}::product/aws/securityhub`,
    GeneratorId: "aws-foundational-security-best-practices/v/1.0.0/EC2.19",
    AwsAccountId: accountId,
    Types: ["Software and Configuration Checks/AWS Security Best Practices/Network Reachability"],
    CreatedAt: "2026-08-07T12:21:00.000Z",
    UpdatedAt: "2026-08-07T12:21:30.000Z",
    Severity: { Label: "CRITICAL", Normalized: 90, Original: "CRITICAL" },
    Title: "Security group allows unrestricted access to a high-risk port",
    Description: "Synthetic finding: TCP 22 is reachable from 0.0.0.0/0.",
    Resources: [{ Type: "AwsEc2SecurityGroup", Id: `arn:aws:ec2:${region}:${accountId}:security-group/${appGroupId}`, Partition: "aws", Region: region, Details: { AwsEc2SecurityGroup: { GroupName: "prod-payments-api", GroupId: appGroupId, OwnerId: accountId, VpcId: "vpc-prod-core", IpPermissions: [{ IpProtocol: "tcp", FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "0.0.0.0/0" }], Ipv6Ranges: [], UserIdGroupPairs: [], PrefixListIds: [] }] } } }],
    Compliance: { Status: "FAILED", SecurityControlId: "EC2.19", AssociatedStandards: [{ StandardsId: "standards/aws-foundational-security-best-practices/v/1.0.0" }] },
    Workflow: { Status: "NEW" },
    RecordState: "ACTIVE",
  }] }),
  "An active ASFF control finding directly identifying the application security group.",
);

const manifest = {
  generatedAt: "2026-08-07T12:30:00.000Z",
  synthetic: true,
  scenario: "A public SSH rule was added to the production payments API. AWS configuration, change, traffic, reachability, service-access, and managed-security evidence describe the resulting activity.",
  accountId,
  region,
  securityGroups: [
    { id: appGroupId, name: "prod-payments-api", expectedRole: "Primary consolidated application finding" },
    { id: edgeGroupId, name: "prod-public-alb", expectedRole: "Consolidated edge-service finding" },
  ],
  intentionalDuplicateRecords: 2,
  expectedUnmatchedSourceTypes: ["network-firewall"],
  files,
};
save("manifest.json", "manifest", json(manifest), "Checksums, source labels, scenario identity, and expected consolidation behavior.");

console.log(JSON.stringify({ outputDirectory, files: files.length - 1, manifest: "manifest.json" }, null, 2));
