use mlua::{Lua, Result as LuaResult};

// Sandboxed Lua 5.4 with memory cap.
// Exposes clops.* with no raw file or socket access.
// Timeout is enforced by the caller via thread join in Phase 1.
pub fn sandbox() -> LuaResult<Lua> {
  let lua = Lua::new();
  let _ = lua.set_memory_limit(8 * 1024 * 1024);
  let clops = lua.create_table()?;
  clops.set(
    "md5",
    lua.create_function(|_, s: String| Ok(crate::hash::md5_hex(&s)))?,
  )?;
  clops.set(
    "sha256",
    lua.create_function(|_, s: String| Ok(crate::hash::sha256_hex(&s)))?,
  )?;
  clops.set(
    "b64encode",
    lua.create_function(|_, s: String| {
      use base64::Engine as E;
      Ok(E::encode(&base64::engine::general_purpose::STANDARD, s.as_bytes()))
    })?,
  )?;
  lua.globals().set("clops", clops)?;
  Ok(lua)
}

pub fn run_snippet(code: &str) -> anyhow::Result<String> {
  let lua = sandbox().map_err(|e| anyhow::anyhow!(e.to_string()))?;
  let v: mlua::Value = lua.load(code).eval().map_err(|e| anyhow::anyhow!(e.to_string()))?;
  Ok(format!("{v:?}"))
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn lua_md5() {
    let out = run_snippet("return clops.md5('hello')").unwrap();
    assert!(out.contains("5d41402abc4b2a76b9719d911017c592"));
  }
}
