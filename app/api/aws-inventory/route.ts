import { loadAwsInventory } from "../../../lib/aws-inventory";
import { apiJson, requestUser } from "../../../lib/server-admin";

export async function GET(request: Request) {
  if (!requestUser(request)) {
    return apiJson({ error: "Authentication is required." }, 401);
  }
  try {
    const inventory = await loadAwsInventory(
      new URL(request.url).searchParams.get("refresh") === "true",
    );
    return apiJson(inventory);
  } catch (error) {
    console.error(
      "AWS inventory load failed",
      error instanceof Error
        ? { name: error.name, message: error.message.slice(0, 240) }
        : { name: "UnknownError" },
    );
    return apiJson(
      {
        error:
          "The AWS security-group inventory is temporarily unavailable. The previous review data remains safe.",
      },
      503,
    );
  }
}
