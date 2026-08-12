export type NetworkExposureStatus = "reachable" | "blocked" | "potential";

export type NetworkExposureClassification =
  | "direct-internet-path"
  | "unattached"
  | "no-internet-route"
  | "no-public-address"
  | "network-acl-blocked"
  | "prerequisites-not-correlated"
  | "managed-service-evidence-incomplete"
  | "evidence-incomplete";

export type NetworkExposureEvidence = {
  subnetIds: string[];
  routeTableIds: string[];
  networkAclIds: string[];
  publicAddressCount: number;
  publicIpv6AddressCount?: number;
  directIpv4InternetPathCount?: number;
  directIpv6InternetPathCount?: number;
  internetGatewayRoute: boolean;
  ipv4InternetGatewayRoute?: boolean;
  ipv6InternetGatewayRoute?: boolean;
  networkAclAllowsInternetIngress: boolean;
  evidenceVersion?: number;
};

export type NetworkExposureAttachment = {
  resourceType?: string | null;
};

export type NetworkExposureAssessment = {
  status: NetworkExposureStatus;
  classification: NetworkExposureClassification;
  reason: string;
  addressFamily: "IPv4" | "IPv6";
};

function mightHideAServiceManagedPublicEndpoint(
  attachments: NetworkExposureAttachment[],
) {
  return attachments.some((attachment) => {
    const type = attachment.resourceType?.toLowerCase() ?? "";
    return (
      type.includes("elasticloadbalancing") ||
      type.includes("loadbalancer") ||
      type.includes("rds") ||
      type.includes("globalaccelerator")
    );
  });
}

/**
 * Determines configured direct internet exposure from independently collected
 * prerequisites. The legacy aggregate `state` is intentionally ignored: early
 * collectors marked an IGW route alone as reachable.
 */
export function assessNetworkExposure(options: {
  evidence?: NetworkExposureEvidence;
  attachments?: NetworkExposureAttachment[];
  attachmentCount: number;
  addressFamily: "IPv4" | "IPv6";
}): NetworkExposureAssessment {
  const {
    evidence,
    attachments = [],
    attachmentCount,
    addressFamily,
  } = options;

  if (attachmentCount === 0) {
    return {
      status: "blocked",
      classification: "unattached",
      addressFamily,
      reason: "The security group has no attached network interfaces or workloads in this snapshot.",
    };
  }

  if (!evidence || !evidence.subnetIds.length || !evidence.routeTableIds.length) {
    return {
      status: "potential",
      classification: "evidence-incomplete",
      addressFamily,
      reason: "Attachment, subnet, or route-table evidence is incomplete.",
    };
  }

  const familyRoute = addressFamily === "IPv4"
    ? evidence.ipv4InternetGatewayRoute
    : evidence.ipv6InternetGatewayRoute;
  const publicAddressCount = addressFamily === "IPv4"
    ? evidence.publicAddressCount
    : evidence.publicIpv6AddressCount;
  const directPathCount = addressFamily === "IPv4"
    ? evidence.directIpv4InternetPathCount
    : evidence.directIpv6InternetPathCount;

  // A legacy combined route flag cannot establish which address family is
  // exposed. Require the family-specific v2 evidence before claiming a path.
  if (
    evidence.evidenceVersion !== 2 ||
    familyRoute === undefined ||
    directPathCount === undefined
  ) {
    return {
      status: "potential",
      classification: "evidence-incomplete",
      addressFamily,
      reason: `The snapshot does not contain family-specific ${addressFamily} route evidence. Re-run the collector before confirming exposure.`,
    };
  }

  if (!familyRoute) {
    return {
      status: "blocked",
      classification: "no-internet-route",
      addressFamily,
      reason: `Attached subnets have route-table evidence but no active ${addressFamily} default route to an attached internet gateway.`,
    };
  }

  if (publicAddressCount === undefined) {
    return {
      status: "potential",
      classification: "evidence-incomplete",
      addressFamily,
      reason: `${addressFamily} address evidence is unavailable for the attached resources.`,
    };
  }

  if (publicAddressCount === 0) {
    if (mightHideAServiceManagedPublicEndpoint(attachments)) {
      return {
        status: "potential",
        classification: "managed-service-evidence-incomplete",
        addressFamily,
        reason: `No direct public ${addressFamily} address was found, but an attached managed service can expose traffic through a service-level public endpoint. Its public-access setting is not present in this snapshot.`,
      };
    }
    return {
      status: "blocked",
      classification: "no-public-address",
      addressFamily,
      reason: `The subnet has an internet-gateway route, but no attached resource has a public ${addressFamily} address. No direct internet path is currently configured.`,
    };
  }

  if (!evidence.networkAclIds.length) {
    return {
      status: "potential",
      classification: "evidence-incomplete",
      addressFamily,
      reason: "Network ACL evidence is unavailable for the attached subnets.",
    };
  }

  if (!evidence.networkAclAllowsInternetIngress) {
    return {
      status: "blocked",
      classification: "network-acl-blocked",
      addressFamily,
      reason: "The resource has a public address and internet-gateway route, but the collected network ACL does not permit internet ingress.",
    };
  }

  if (directPathCount === 0) {
    return {
      status: "blocked",
      classification: "prerequisites-not-correlated",
      addressFamily,
      reason: `Public ${addressFamily} address, route, and NACL signals exist in the group, but they do not converge on the same attached network interface.`,
    };
  }

  return {
    status: "reachable",
    classification: "direct-internet-path",
    addressFamily,
    reason: `AWS configuration shows an attached public ${addressFamily} address, an active internet-gateway route, and an internet-ingress NACL allow. This proves a configured network path, not a listening service or successful connection.`,
  };
}

export function networkExposureRiskAdjustment(
  assessments: NetworkExposureAssessment[],
  attached: boolean,
) {
  if (assessments.some((assessment) => assessment.status === "reachable")) return 0;
  if (assessments.some((assessment) => assessment.status === "potential")) return 5;
  return attached ? 25 : 35;
}
