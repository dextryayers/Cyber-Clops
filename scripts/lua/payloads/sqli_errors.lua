-- SQLi error signatures for T10. Safe detect only.
local M = {
  { db = "MySQL", re = "You have an error in your SQL syntax" },
  { db = "MySQL", re = "mysql_fetch_" },
  { db = "Postgres", re = "PG::SyntaxError" },
  { db = "Postgres", re = "unterminated quoted string" },
  { db = "MSSQL", re = "Unclosed quotation mark" },
  { db = "Oracle", re = "ORA%-01756" },
  { db = "SQLite", re = "SQLite3::SQLException" },
}
return M
