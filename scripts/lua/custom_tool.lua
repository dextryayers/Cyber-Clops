-- Custom tool template for Lua. Renders a simple panel in Phase 2.
-- English labels only.
local tool = {}
tool.name = "Hello Lab"
tool.description = "Example custom tool. Edit this file to add your own check."

function tool.run(target)
  return "checked " .. target .. " md5=" .. clops.md5(target)
end

return tool
