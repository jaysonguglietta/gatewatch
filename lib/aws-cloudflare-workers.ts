import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import {
  DatabaseSync,
  type SQLInputValue,
} from "node:sqlite";

type Row = Record<string, unknown>;

const databasePath = process.env.GATEWATCH_SQLITE_PATH ?? "/data/gatewatch.sqlite";
if (databasePath !== ":memory:") {
  mkdirSync(dirname(databasePath), { recursive: true });
}

const database = new DatabaseSync(databasePath, {
  enableForeignKeyConstraints: true,
});
database.exec("PRAGMA busy_timeout = 5000; PRAGMA journal_mode = DELETE;");

function sqlValue(value: unknown): SQLInputValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "bigint" ||
    ArrayBuffer.isView(value)
  ) {
    return value as SQLInputValue;
  }
  if (typeof value === "boolean") return value ? 1 : 0;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new TypeError("Unsupported database binding value");
}

class AwsD1PreparedStatement implements D1PreparedStatement {
  readonly query: string;
  readonly values: unknown[];

  constructor(query: string, values: unknown[] = []) {
    this.query = query;
    this.values = values;
  }

  bind(...values: unknown[]): D1PreparedStatement {
    return new AwsD1PreparedStatement(this.query, values);
  }

  async run() {
    const result = database.prepare(this.query).run(...this.values.map(sqlValue));
    return {
      success: true,
      results: [],
      meta: {
        changes: result.changes,
        last_row_id: Number(result.lastInsertRowid),
      },
    };
  }

  async all<T = Row>() {
    const rows = database.prepare(this.query).all(...this.values.map(sqlValue));
    return {
      results: rows.map((row) => ({ ...row })) as T[],
    };
  }

  async first<T = Row>() {
    const row = database.prepare(this.query).get(...this.values.map(sqlValue));
    return row ? ({ ...row } as T) : null;
  }
}

class AwsD1Database implements D1Database {
  prepare(query: string) {
    return new AwsD1PreparedStatement(query);
  }

  async batch(statements: D1PreparedStatement[]) {
    database.exec("BEGIN IMMEDIATE");
    try {
      const results = [];
      for (const statement of statements) {
        if (!(statement instanceof AwsD1PreparedStatement)) {
          throw new TypeError("Unsupported database statement implementation");
        }
        if (/^\s*(select|pragma|with)\b/i.test(statement.query)) {
          results.push(await statement.all());
        } else {
          results.push(await statement.run() as { results: Row[] });
        }
      }
      database.exec("COMMIT");
      return results;
    } catch (error) {
      database.exec("ROLLBACK");
      throw error;
    }
  }
}

const runtimeEnvironment = new Proxy(
  { DB: new AwsD1Database() } as { DB: D1Database } & Record<string, unknown>,
  {
    get(target, property: string) {
      if (property === "DB") return target.DB;
      return process.env[property];
    },
  },
);

export const env = runtimeEnvironment;
