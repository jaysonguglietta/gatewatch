export class HttpInputError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "HttpInputError";
    this.status = status;
  }
}
function jsonContentType(value: string | null) {
  const mediaType = value?.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  return mediaType === "application/json" || mediaType.endsWith("+json");
}

/**
 * Read and parse a JSON request without trusting Content-Length.
 *
 * The stream is cancelled as soon as the byte limit is crossed, which protects
 * endpoints from chunked requests and clients that omit or forge the declared
 * length. The declared length is still checked as an inexpensive early reject.
 */
export async function readBoundedJson<T = Record<string, unknown>>(
  request: Request,
  maxBytes: number,
): Promise<T> {
  if (!jsonContentType(request.headers.get("content-type"))) {
    throw new HttpInputError(415, "Content-Type must be application/json.");
  }

  const declaredHeader = request.headers.get("content-length");
  if (declaredHeader !== null) {
    if (!/^\d+$/.test(declaredHeader)) {
      throw new HttpInputError(400, "Content-Length must be a non-negative integer.");
    }
    if (Number(declaredHeader) > maxBytes) {
      throw new HttpInputError(413, "The request is too large.");
    }
  }

  const chunks: Uint8Array[] = [];
  let received = 0;
  const reader = request.body?.getReader();
  if (reader) {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maxBytes) {
        await reader.cancel("Gatewatch request-size limit exceeded");
        throw new HttpInputError(413, "The request is too large.");
      }
      chunks.push(value);
    }
  }

  const bytes = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new HttpInputError(400, "The JSON request must use valid UTF-8.");
  }
  if (!text.trim()) throw new HttpInputError(400, "The JSON request body is required.");

  try {
    return JSON.parse(text) as T;
  } catch {
    throw new HttpInputError(400, "Request body must be valid JSON.");
  }
}
