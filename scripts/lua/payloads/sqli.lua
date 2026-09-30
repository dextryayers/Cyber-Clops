-- T10 SQLi safe payloads. Detect only. No dump. No stacked destructive query.
-- Each entry documents purpose and risk.
local M = {
  { id = "sqli-quote", param = "id", payload = "'", purpose = "Trigger DB error message", risk = "Low" },
  { id = "sqli-dquote", param = "id", payload = '"', purpose = "Trigger DB error for double quote context", risk = "Low" },
  { id = "sqli-bool-true", param = "id", payload = "1' AND '1'='1", purpose = "Boolean true branch", risk = "Low" },
  { id = "sqli-bool-false", param = "id", payload = "1' AND '1'='2", purpose = "Boolean false branch for diff", risk = "Low" },
}
return M
