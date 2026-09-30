use rusqlite::{params, Connection};
use std::path::Path;

pub struct Store {
  conn: Connection,
}

impl Store {
  pub fn open(path: &Path) -> anyhow::Result<Self> {
    let conn = Connection::open(path)?;
    Ok(Self { conn })
  }

  pub fn open_memory() -> anyhow::Result<Self> {
    Ok(Self { conn: Connection::open_in_memory()? })
  }

  pub fn migrate(&self) -> anyhow::Result<()> {
    let sql = include_str!("../migrations/001_init.sql");
    self.conn.execute_batch(sql)?;
    Ok(())
  }

  pub fn add_port(&self, project: &str, host: &str, port: i64, state: &str, service: &str) -> anyhow::Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    self.conn.execute(
      "INSERT INTO ports (id, project_id, host, port, state, service) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
      params![id, project, host, port, state, service],
    )?;
    Ok(())
  }

  pub fn count_ports(&self, project: &str) -> anyhow::Result<i64> {
    Ok(self.conn.query_row(
      "SELECT COUNT(*) FROM ports WHERE project_id = ?1",
      params![project],
      |r| r.get(0),
    )?)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn migrate_and_insert() {
    let s = Store::open_memory().unwrap();
    s.migrate().unwrap();
    s.add_port("p1", "127.0.0.1", 80, "open", "http").unwrap();
    assert_eq!(s.count_ports("p1").unwrap(), 1);
  }
}
