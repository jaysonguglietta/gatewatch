export type InternetExposure = "internet" | "no-internet" | "unknown";

export type ExposureSortableFinding = {
  verdict: string;
  riskScore: number;
  fingerprint: string;
};

export function internetExposureForVerdict(verdict: string): InternetExposure {
  if (["Internet path exists", "Confirmed public service"].includes(verdict)) {
    return "internet";
  }
  if (
    ["Broad but unreachable", "Internal only", "Internal path confirmed"].includes(
      verdict,
    )
  ) {
    return "no-internet";
  }
  return "unknown";
}

export function compareInternetExposure(
  left: ExposureSortableFinding,
  right: ExposureSortableFinding,
  priority: "internet" | "no-internet",
) {
  const ranks: Record<InternetExposure, number> = priority === "internet"
    ? { internet: 0, unknown: 1, "no-internet": 2 }
    : { "no-internet": 0, unknown: 1, internet: 2 };
  const rankDifference =
    ranks[internetExposureForVerdict(left.verdict)] -
    ranks[internetExposureForVerdict(right.verdict)];
  if (rankDifference) return rankDifference;
  return right.riskScore - left.riskScore ||
    left.fingerprint.localeCompare(right.fingerprint);
}
