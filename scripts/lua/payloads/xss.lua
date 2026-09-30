-- T11 XSS reflected safe markers. No real script execution needed for detect.
-- Uses neutral marker clopsXYZ plus context probe. Double send required by engine.
local M = {
  { id = "xss-marker", payload = "clopsXYZ123", purpose = "Reflection test", risk = "Low" },
  { id = "xss-attr-dq", payload = '"clopsXYZ123"', purpose = "Attribute double quote context", risk = "Low" },
  { id = "xss-attr-sq", payload = "'clopsXYZ123'", purpose = "Attribute single quote context", risk = "Low" },
  { id = "xss-tag", payload = "<b>clopsXYZ123</b>", purpose = "HTML text context, safe tag", risk = "Low" },
}
return M
