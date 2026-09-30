-- Service probes for T03. Pure data, no sockets here.
-- Engine calls probe_for(port, banner) to refine service and version.
local M = {}

function M.probe_for(port, banner)
  banner = banner or ""
  if banner:sub(1, 4) == "SSH-" then
    return "ssh", banner:match("[^\r\n]+") or ""
  end
  if banner:sub(1, 3) == "220" then
    return "ftp-or-smtp", banner:match("[^\r\n]+") or ""
  end
  if port == 80 or port == 8000 or port == 8080 or port == 18080 then
    return "http", ""
  end
  if port == 443 or port == 8443 or port == 18443 then
    return "https", ""
  end
  return "unknown", ""
end

return M
