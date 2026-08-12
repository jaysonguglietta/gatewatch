import { loadOrganizationCoverage } from "../../../lib/organization-coverage";
import { apiJson, requestUser } from "../../../lib/server-admin";

export async function GET(request: Request) {
  if (!requestUser(request)) {
    return apiJson({ error: "Authentication is required." }, 401);
  }
  try {
    return apiJson({ coverage: await loadOrganizationCoverage() });
  } catch (error) {
    console.error(
      "Organization coverage load failed",
      error instanceof Error
        ? { name: error.name, message: error.message.slice(0, 160) }
        : { name: "UnknownError" },
    );
    return apiJson(
      {
        error:
          "Organization collection coverage is not connected yet. Existing snapshot coverage remains available.",
      },
      503,
    );
  }
}
