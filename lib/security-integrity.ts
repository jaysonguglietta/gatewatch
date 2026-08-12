function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, item]) => item !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, canonicalValue(item)]),
    );
  }
  if (typeof value === "number" && !Number.isFinite(value)) return null;
  return value;
}
export function canonicalJson(value: unknown) {
  return JSON.stringify(canonicalValue(value));
}

export async function sha256Hex(value: string) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export type RemediationDigestInput = {
  fingerprint: string;
  canonicalResourceKey: string;
  proposedChange: string;
  artifactType: string;
  evidenceBefore: unknown;
};

export function canonicalRemediation(input: RemediationDigestInput) {
  return canonicalJson({
    artifactType: input.artifactType,
    canonicalResourceKey: input.canonicalResourceKey,
    evidenceBefore: input.evidenceBefore,
    fingerprint: input.fingerprint,
    proposedChange: input.proposedChange,
  });
}

export function remediationDigest(input: RemediationDigestInput) {
  return sha256Hex(canonicalRemediation(input));
}
