import assert from "node:assert/strict";
import test from "node:test";
import {
  consolidateInfrastructureReviews,
  reviewInfrastructureFile,
} from "../lib/iac-security-review.ts";

const cloudFormationYaml = `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  InternetGateway:
    Type: AWS::EC2::InternetGateway
  PublicRoute:
    Type: AWS::EC2::Route
    Properties:
      RouteTableId: !Ref PublicRouteTable
      DestinationCidrBlock: 0.0.0.0/0
      GatewayId: !Ref InternetGateway
  PublicInterface:
    Type: AWS::EC2::NetworkInterface
    Properties:
      AssociatePublicIpAddress: true
      GroupSet: [!Ref WebSecurityGroup]
  WebSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Public web tier
      VpcId: !Ref Vpc
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIpv6: ::/0
          Description: Public HTTPS
`;

const terraformHcl = `variable "admin_cidr" {
  default = "0.0.0.0/0"
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route" "public" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_instance" "bastion" {
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.bastion.id]
}

resource "aws_security_group" "bastion" {
  name        = "prod-bastion"
  description = "Managed administration"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Temporary public SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`;

test("parses CloudFormation YAML, intrinsic tags, line evidence, and public path signals", () => {
  const review = reviewInfrastructureFile("network.yaml", cloudFormationYaml);
  assert.equal(review.status, "parsed");
  assert.equal(review.format, "cloudformation-yaml");
  assert.equal(review.groups.length, 1);
  const [group] = review.groups;
  assert.equal(group.name, "WebSecurityGroup");
  assert.equal(group.rules.length, 2);
  assert.equal(group.exposure, "potential-internet");
  assert.equal(group.verdict, "block");
  assert.ok(group.issues.some((issue) => /Administrative access/.test(issue.title)));
  assert.ok(group.rules.every((rule) => rule.line > 0));
});

test("preserves unresolved CloudFormation CIDR intrinsics for review", () => {
  const review = reviewInfrastructureFile("parameterized.yaml", `Parameters:
  TrustedCidr:
    Type: String
Resources:
  ParameterizedGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Parameterized access
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: !Ref TrustedCidr
`);
  assert.equal(review.status, "parsed");
  assert.deepEqual(review.groups[0].rules[0].sources, ["Ref:TrustedCidr"]);
  assert.equal(review.groups[0].rules[0].unresolved, true);
  assert.ok(review.groups[0].issues.some((issue) => /unresolved expressions/.test(issue.title)));
});

test("parses Terraform HCL, resolves simple variable defaults, and consolidates nested rules", () => {
  const review = reviewInfrastructureFile("main.tf", terraformHcl);
  assert.equal(review.status, "parsed");
  assert.equal(review.format, "terraform-hcl");
  assert.equal(review.groups.length, 1);
  const [group] = review.groups;
  assert.equal(group.name, "prod-bastion");
  assert.equal(group.rules.length, 2);
  assert.deepEqual(group.rules[0].sources, ["0.0.0.0/0"]);
  assert.equal(group.exposure, "potential-internet");
  assert.ok(group.issues.some((issue) => issue.severity === "critical"));
  assert.ok(group.issues.some((issue) => /Unrestricted internet egress/.test(issue.title)));
});

test("parses standalone Terraform rule resources and Terraform JSON", () => {
  const hcl = reviewInfrastructureFile("rules.tf", `resource "aws_vpc_security_group_ingress_rule" "db" {
  security_group_id = aws_security_group.database.id
  from_port = 5432
  to_port = 5432
  ip_protocol = "tcp"
  cidr_ipv4 = "0.0.0.0/0"
}`);
  assert.equal(hcl.status, "parsed");
  assert.equal(hcl.groups[0].key, "terraform:aws_security_group.database");
  assert.ok(hcl.groups[0].issues.some((issue) => /Database/.test(issue.title)));

  const json = reviewInfrastructureFile("network.tf.json", JSON.stringify({
    resource: {
      aws_security_group: {
        web: {
          name: "web",
          ingress: [{ from_port: 80, to_port: 80, protocol: "tcp", cidr_blocks: ["0.0.0.0/0"], description: "HTTP" }],
        },
      },
    },
  }));
  assert.equal(json.status, "parsed");
  assert.equal(json.groups[0].rules[0].fromPort, 80);
  assert.equal(json.groups[0].verdict, "review");

  const referenced = reviewInfrastructureFile("private.tf.json", JSON.stringify({ resource: { aws_security_group: { service: { description: "Private service", ingress: [{ description: "Load balancer only", from_port: 8443, to_port: 8443, protocol: "tcp", source_security_group_id: "${aws_security_group.internal_lb.id}" }] } } } }));
  assert.equal(referenced.status, "parsed");
  assert.equal(referenced.groups[0].exposure, "internal-only");
  assert.equal(referenced.groups[0].verdict, "pass");
});

test("detects CloudFormation JSON and standalone security-group ingress", () => {
  const review = reviewInfrastructureFile("template.json", JSON.stringify({
    Resources: {
      DatabaseSecurityGroup: { Type: "AWS::EC2::SecurityGroup", Properties: { GroupDescription: "Database", VpcId: { Ref: "Vpc" } } },
      PublicDatabaseRule: { Type: "AWS::EC2::SecurityGroupIngress", Properties: { GroupId: { Ref: "DatabaseSecurityGroup" }, IpProtocol: "tcp", FromPort: 3306, ToPort: 3306, CidrIp: "0.0.0.0/0" } },
    },
  }));
  assert.equal(review.status, "parsed");
  assert.equal(review.groups.length, 1);
  assert.equal(review.groups[0].rules.length, 1);
  assert.equal(review.groups[0].verdict, "block");
});

test("fails closed on unsupported, empty, oversized, and malformed files", () => {
  assert.equal(reviewInfrastructureFile("README.md", "resource {} ").status, "rejected");
  assert.equal(reviewInfrastructureFile("empty.tf", " ").status, "rejected");
  assert.equal(reviewInfrastructureFile("broken.yaml", "Resources: [").status, "rejected");
  assert.equal(reviewInfrastructureFile("large.tf", "x".repeat(5 * 1024 * 1024 + 1)).status, "rejected");
  const aliases = Array.from({ length: 60 }, () => "    - *shared").join("\n");
  const aliasReview = reviewInfrastructureFile("aliases.yaml", `Metadata:
  Shared: &shared unrestricted
  Repeated:
${aliases}
Resources:
  EmptyGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Alias limit test
`);
  assert.equal(aliasReview.status, "rejected");
  assert.match(aliasReview.error ?? "", /alias/i);
});

test("consolidates rules from multiple files into one security-group review", () => {
  const group = reviewInfrastructureFile("group.tf", `resource "aws_security_group" "web" { name = "web" }`);
  const rule = reviewInfrastructureFile("rule.tf", `resource "aws_security_group_rule" "https" {
  type = "ingress"
  security_group_id = aws_security_group.web.id
  from_port = 443
  to_port = 443
  protocol = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  description = "HTTPS"
}`);
  const batch = consolidateInfrastructureReviews([group, rule]);
  assert.equal(batch.totals.parsedFiles, 2);
  assert.equal(batch.groups.length, 1);
  assert.deepEqual(batch.groups[0].fileNames.sort(), ["group.tf", "rule.tf"]);
  assert.equal(batch.groups[0].rules.length, 1);
});
