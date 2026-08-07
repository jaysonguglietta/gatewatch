import assert from "node:assert/strict";
import test from "node:test";
import {
  dailyFindingMatchReasons,
  dailyFindingMatchesQuery,
  parseDailyFindingQuery,
  securityGroupArnForFinding,
} from "../lib/daily-finding-query.ts";

const finding = {
  securityGroupArn: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789abcdef0",
  canonicalResourceKey: "aws:123456789012:us-east-1:vpc-0123:security-group:sg-0123456789abcdef0",
  securityGroupId: "sg-0123456789abcdef0",
  securityGroupName: "payments edge",
  accountId: "123456789012",
  accountName: "Production Payments",
  region: "us-east-1",
  vpcId: "vpc-0123",
  title: "Public HTTPS ingress",
  ruleSummary: "Ingress TCP/443 from 0.0.0.0/0",
  severity: "critical",
  riskScore: 88,
  verdict: "Internet path confirmed",
  status: "new",
  owner: "Cloud Security",
  assignee: "Payments Platform",
  application: "Checkout API",
  environment: "Production",
  organizationalUnit: "Finance / Production",
  policyName: "Public listener policy",
  policyControl: "GW-NET-001",
  pathSummary: "1 confirmed path; Internet gateway → public ALB",
  changeActor: "arn:aws:iam::123456789012:role/network-admin",
  changeSummary: "AuthorizeSecurityGroupIngress by network-admin through Terraform",
  ageDays: 42,
  lastSeenAt: "2026-07-30T12:00:00.000Z",
  observationCount: 4,
  changeTime: "2026-07-21T09:30:00.000Z",
  evidence: {
    state: "observed",
    confidence: 95,
    sources: ["AWS Config", "VPC Flow Logs"],
    limitations: [],
  },
  attachments: [{
    id: "alb-payments",
    name: "payments-public-alb",
    type: "ALB",
    publicAddress: "198.51.100.10",
    vpcId: "vpc-0123",
    arn: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/payments/1234",
    tags: { Environment: "Production", DataClass: "PCI" },
  }],
};

function matches(query, target = finding) {
  return dailyFindingMatchesQuery(target, parseDailyFindingQuery(query));
}

test("searches canonical security-group identity and quoted names", () => {
  assert.equal(matches(finding.securityGroupArn), true);
  assert.equal(matches(`arn:${finding.securityGroupArn}`), true);
  assert.equal(matches("sg:sg-0123456789abcdef0"), true);
  assert.equal(matches('name:"payments edge" account:123456789012 region:us-east-1'), true);
  assert.equal(matches("account:staging"), false);
});

test("searches ingress configuration with AND semantics", () => {
  assert.equal(matches('ingress:"TCP/443" source:0.0.0.0/0 protocol:tcp port:443'), true);
  assert.equal(matches("egress:443"), false);
  assert.equal(matches("ingress:443 source:10.0.0.0/8"), false);
  assert.equal(matches("Public payments"), true);
  assert.equal(matches("Public database"), false);
});

test("searches workflow, resource, tag, evidence, and numeric fields", () => {
  assert.equal(matches('owner:"Cloud Security" assignee:"Payments Platform" status:new'), true);
  assert.equal(matches("resource:payments-public-alb tag:DataClass:PCI evidence:config"), true);
  assert.equal(matches("risk:>=80 confidence:90-100 age:>30"), true);
  assert.equal(matches("risk:<80"), false);
});

test("reports malformed queries instead of treating them as valid empty searches", () => {
  const unsupported = parseDailyFindingQuery("cloud-account:123456789012");
  assert.deepEqual(unsupported.unsupportedFields, ["cloud-account"]);
  assert.equal(dailyFindingMatchesQuery(finding, unsupported), false);

  const unclosed = parseDailyFindingQuery('name:"payments edge');
  assert.equal(unclosed.unclosedQuote, true);
  assert.equal(dailyFindingMatchesQuery(finding, unclosed), false);
});

test("infers partition-correct ARNs when older records do not include one", () => {
  const govCloudFinding = {
    ...finding,
    securityGroupArn: undefined,
    accountId: "210987654321",
    region: "us-gov-west-1",
  };
  assert.equal(
    securityGroupArnForFinding(govCloudFinding),
    "arn:aws-us-gov:ec2:us-gov-west-1:210987654321:security-group/sg-0123456789abcdef0",
  );
  assert.equal(matches("arn:aws-us-gov:ec2:us-gov-west-1:210987654321:security-group/sg-0123456789abcdef0", govCloudFinding), true);
});

test("supports OR, NOT, parentheses, and conventional precedence", () => {
  assert.equal(matches("port:22 OR port:443"), true);
  assert.equal(matches("(port:22 OR port:443) AND NOT account:staging"), true);
  assert.equal(matches("port:443 OR port:22 AND account:staging"), true, "AND binds more tightly than OR");
  assert.equal(matches("(port:22 OR port:80) AND account:staging"), false);
  assert.equal(matches("NOT (internet:none OR status:resolved)"), true);
});

test("searches change history, internet state, and recurrence", () => {
  assert.equal(matches("internet:confirmed recurrence:>=3 changed-after:2026-07-01 changed-before:2026-07-31"), true);
  assert.equal(matches("changed-by:network-admin"), true);
  assert.equal(matches("recurrence:>4"), false);
});

test("explains positive matched clauses without presenting excluded terms as evidence", () => {
  const parsed = parseDailyFindingQuery("account:123456789012 AND ingress:443 AND NOT status:resolved");
  assert.deepEqual(dailyFindingMatchReasons(finding, parsed), [
    "Account: 123456789012",
    "Ingress rule: 443",
  ]);
});

test("bounds Boolean query complexity and reports syntax errors", () => {
  const trailing = parseDailyFindingQuery("account:123456789012 OR");
  assert.match(trailing.syntaxErrors.join(" "), /OR must be followed/);
  assert.equal(dailyFindingMatchesQuery(finding, trailing), false);
  const tooMany = parseDailyFindingQuery(Array.from({ length: 41 }, () => "region:us-east-1").join(" AND "));
  assert.equal(tooMany.complexityExceeded, true);
  assert.equal(dailyFindingMatchesQuery(finding, tooMany), false);
});
