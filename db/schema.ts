import { sql } from "drizzle-orm";
import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const securityGroupReviews = sqliteTable("security_group_reviews", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  securityGroupId: text("security_group_id").notNull().unique(),
  status: text("status").notNull().default("needs-review"),
  assignee: text("assignee").notNull().default("Unassigned"),
  note: text("note").notNull().default(""),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});
