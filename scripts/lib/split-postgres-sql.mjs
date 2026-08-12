export function splitPostgresSql(source) {
  const statements = [];
  let statement = "";
  let dollarTag = "";
  let singleQuoted = false;
  let doubleQuoted = false;
  let lineComment = false;
  let blockCommentDepth = 0;

  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1] ?? "";

    if (lineComment) {
      statement += char;
      if (char === "\n") lineComment = false;
      continue;
    }
    if (blockCommentDepth > 0) {
      statement += char;
      if (char === "/" && next === "*") {
        statement += next;
        blockCommentDepth += 1;
        index += 1;
      } else if (char === "*" && next === "/") {
        statement += next;
        blockCommentDepth -= 1;
        index += 1;
      }
      continue;
    }
    if (dollarTag) {
      if (source.startsWith(dollarTag, index)) {
        statement += dollarTag;
        index += dollarTag.length - 1;
        dollarTag = "";
      } else {
        statement += char;
      }
      continue;
    }
    if (singleQuoted) {
      statement += char;
      if (char === "'" && next === "'") {
        statement += next;
        index += 1;
      } else if (char === "'") {
        singleQuoted = false;
      }
      continue;
    }
    if (doubleQuoted) {
      statement += char;
      if (char === '"' && next === '"') {
        statement += next;
        index += 1;
      } else if (char === '"') {
        doubleQuoted = false;
      }
      continue;
    }

    if (char === "-" && next === "-") {
      statement += char + next;
      lineComment = true;
      index += 1;
      continue;
    }
    if (char === "/" && next === "*") {
      statement += char + next;
      blockCommentDepth = 1;
      index += 1;
      continue;
    }
    if (char === "'") {
      singleQuoted = true;
      statement += char;
      continue;
    }
    if (char === '"') {
      doubleQuoted = true;
      statement += char;
      continue;
    }
    if (char === "$") {
      const match = source.slice(index).match(/^\$[A-Za-z_][A-Za-z0-9_]*\$|^\$\$/);
      if (match) {
        dollarTag = match[0];
        statement += dollarTag;
        index += dollarTag.length - 1;
        continue;
      }
    }
    if (char === ";") {
      if (statement.trim()) statements.push(statement.trim());
      statement = "";
      continue;
    }
    statement += char;
  }

  if (singleQuoted || doubleQuoted || dollarTag || blockCommentDepth > 0) {
    throw new Error("PostgreSQL migration contains an unterminated quoted value or comment");
  }
  if (statement.trim()) statements.push(statement.trim());
  return statements;
}
