type RuntimeCredentials = {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  expiration: Date;
};

let cached: RuntimeCredentials | null = null;

async function metadataRequest(path: string, token: string) {
  const response = await fetch(`http://169.254.169.254/latest/${path}`, {
    headers: { "x-aws-ec2-metadata-token": token },
    signal: AbortSignal.timeout(3_000),
  });
  if (!response.ok) throw new Error("AWS_RUNTIME_METADATA_UNAVAILABLE");
  return response.text();
}

export async function awsRuntimeCredentials(): Promise<RuntimeCredentials> {
  if (
    cached &&
    cached.expiration.getTime() - Date.now() > 5 * 60_000
  ) {
    return cached;
  }

  const tokenResponse = await fetch(
    "http://169.254.169.254/latest/api/token",
    {
      method: "PUT",
      headers: { "x-aws-ec2-metadata-token-ttl-seconds": "21600" },
      signal: AbortSignal.timeout(3_000),
    },
  );
  if (!tokenResponse.ok) throw new Error("AWS_RUNTIME_METADATA_TOKEN_FAILED");
  const token = await tokenResponse.text();
  const roleName = (
    await metadataRequest("meta-data/iam/security-credentials/", token)
  ).trim();
  if (!/^[A-Za-z0-9+=,.@_-]{1,128}$/.test(roleName)) {
    throw new Error("AWS_RUNTIME_ROLE_INVALID");
  }
  const raw = await metadataRequest(
    `meta-data/iam/security-credentials/${encodeURIComponent(roleName)}`,
    token,
  );
  const value = JSON.parse(raw) as Record<string, unknown>;
  if (
    value.Code !== "Success" ||
    typeof value.AccessKeyId !== "string" ||
    typeof value.SecretAccessKey !== "string" ||
    typeof value.Token !== "string" ||
    typeof value.Expiration !== "string"
  ) {
    throw new Error("AWS_RUNTIME_CREDENTIALS_INVALID");
  }
  const expiration = new Date(value.Expiration);
  if (!Number.isFinite(expiration.getTime())) {
    throw new Error("AWS_RUNTIME_CREDENTIAL_EXPIRATION_INVALID");
  }
  cached = {
    accessKeyId: value.AccessKeyId,
    secretAccessKey: value.SecretAccessKey,
    sessionToken: value.Token,
    expiration,
  };
  return cached;
}

