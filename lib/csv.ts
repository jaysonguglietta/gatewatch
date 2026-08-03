/** Encode a value as a CSV cell without allowing spreadsheet formula execution. */
export function csvCell(value: unknown) {
  const raw = String(value ?? "");
  const safe = /^[\s]*[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  return `"${safe.replaceAll('"', '""')}"`;
}

export function csvDocument(rows: readonly (readonly unknown[])[]) {
  return rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
}
