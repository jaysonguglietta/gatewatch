import { sql } from "drizzle-orm";
import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const securityGroupReviews = sqliteTable("security_group_reviews", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  securityGroupId: text("security_group_id").notNull().unique(),
  status: text("status").notNull().default("needs-review"),
  assignee: text("assignee").notNull().default("Unassigned"),
  reviewer: text("reviewer").notNull().default(""),
  note: text("note").notNull().default(""),
  ticketRef: text("ticket_ref").notNull().default(""),
  expiresAt: text("expires_at").notNull().default(""),
  evidenceSnapshot: text("evidence_snapshot").notNull().default(""),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const securityGroupReviewEvents = sqliteTable(
  "security_group_review_events",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    securityGroupId: text("security_group_id").notNull(),
    status: text("status").notNull(),
    assignee: text("assignee").notNull(),
    reviewer: text("reviewer").notNull().default(""),
    note: text("note").notNull(),
    ticketRef: text("ticket_ref").notNull().default(""),
    expiresAt: text("expires_at").notNull().default(""),
    evidenceSnapshot: text("evidence_snapshot").notNull().default(""),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("security_group_review_events_group_idx").on(
      table.securityGroupId,
      table.createdAt,
    ),
  ],
);
