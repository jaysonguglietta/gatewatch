import assert from "node:assert/strict";
import test from "node:test";

import {
  assessNetworkExposure,
  networkExposureRiskAdjustment,
} from "../lib/network-exposure.ts";

const completeEvidence = {
  evidenceVersion: 2,
  subnetIds: ["subnet-1"],
  routeTableIds: ["rtb-1"],
  networkAclIds: ["acl-1"],
  publicAddressCount: 1,
  publicIpv6AddressCount: 0,
  directIpv4InternetPathCount: 1,
  directIpv6InternetPathCount: 0,
  internetGatewayRoute: true,
  ipv4InternetGatewayRoute: true,
  ipv6InternetGatewayRoute: false,
  networkAclAllowsInternetIngress: true,
};

test("requires every direct IPv4 internet-path prerequisite", () => {
  const result = assessNetworkExposure({
    evidence: completeEvidence,
    attachmentCount: 1,
    addressFamily: "IPv4",
  });
  assert.equal(result.status, "reachable");
  assert.equal(result.classification, "direct-internet-path");
});

test("does not treat an IGW route without a public address as reachable", () => {
  const result = assessNetworkExposure({
    evidence: {
      ...completeEvidence,
      publicAddressCount: 0,
      directIpv4InternetPathCount: 0,
    },
    attachmentCount: 1,
    addressFamily: "IPv4",
  });
  assert.equal(result.status, "blocked");
  assert.equal(result.classification, "no-public-address");
  assert.match(result.reason, /no attached resource has a public IPv4 address/i);
});

test("does not treat a public address without an IGW route as reachable", () => {
  const result = assessNetworkExposure({
    evidence: {
      ...completeEvidence,
      internetGatewayRoute: false,
      ipv4InternetGatewayRoute: false,
      directIpv4InternetPathCount: 0,
    },
    attachmentCount: 1,
    addressFamily: "IPv4",
  });
  assert.equal(result.status, "blocked");
  assert.equal(result.classification, "no-internet-route");
});

test("does not treat an NACL-blocked path as reachable", () => {
  const result = assessNetworkExposure({
    evidence: {
      ...completeEvidence,
      networkAclAllowsInternetIngress: false,
      directIpv4InternetPathCount: 0,
    },
    attachmentCount: 1,
    addressFamily: "IPv4",
  });
  assert.equal(result.status, "blocked");
  assert.equal(result.classification, "network-acl-blocked");
});

test("treats legacy combined route evidence as incomplete", () => {
  const legacy = {
    subnetIds: ["subnet-1"],
    routeTableIds: ["rtb-1"],
    networkAclIds: ["acl-1"],
    publicAddressCount: 1,
    internetGatewayRoute: true,
    networkAclAllowsInternetIngress: true,
  };
  const result = assessNetworkExposure({
    evidence: legacy,
    attachmentCount: 1,
    addressFamily: "IPv4",
  });
  assert.equal(result.status, "potential");
  assert.equal(result.classification, "evidence-incomplete");
});

test("requires service-level evidence for managed public endpoints", () => {
  const result = assessNetworkExposure({
    evidence: {
      ...completeEvidence,
      publicAddressCount: 0,
      directIpv4InternetPathCount: 0,
    },
    attachments: [{ resourceType: "AWS::ElasticLoadBalancingV2::LoadBalancer" }],
    attachmentCount: 1,
    addressFamily: "IPv4",
  });
  assert.equal(result.status, "potential");
  assert.equal(result.classification, "managed-service-evidence-incomplete");
});

test("does not combine prerequisites from different attachments", () => {
  const result = assessNetworkExposure({
    evidence: { ...completeEvidence, directIpv4InternetPathCount: 0 },
    attachmentCount: 2,
    addressFamily: "IPv4",
  });
  assert.equal(result.status, "blocked");
  assert.equal(result.classification, "prerequisites-not-correlated");
});

test("classifies unattached broad groups as blocked", () => {
  const result = assessNetworkExposure({
    evidence: completeEvidence,
    attachmentCount: 0,
    addressFamily: "IPv4",
  });
  assert.equal(result.status, "blocked");
  assert.equal(result.classification, "unattached");
});

test("reduces risk for blocked paths without reducing incomplete evidence as much", () => {
  const reachable = { status: "reachable" };
  const blocked = { status: "blocked" };
  const potential = { status: "potential" };
  assert.equal(networkExposureRiskAdjustment([reachable], true), 0);
  assert.equal(networkExposureRiskAdjustment([potential], true), 5);
  assert.equal(networkExposureRiskAdjustment([blocked], true), 25);
  assert.equal(networkExposureRiskAdjustment([blocked], false), 35);
});
