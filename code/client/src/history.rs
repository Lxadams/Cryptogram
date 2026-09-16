//! Local, per-identity chat history backed by SQLite + SQLCipher.
//!
//! Each peer keeps a full, independent copy of every conversation it has
//! ever had — there is no shared/synced history between peers (matches how
//! `identities/<pseudonym>/` already works: everything under it is local to
//! this machine and this identity only). The database lives right next to
//! `client_state.json` under the same identity directory, keyed by the same
//! Argon2id-derived vault key the login passcode unlocks (see
//! `derive_vault_key` in `lib.rs`).
//!
//! Deliberately minimal: one table, hex-encoded routing token as the
//! conversation key (matches every other per-contact map in `Client`), and
//! callers pull only as much history as they need (`recent`) rather than
//! this module ever handing back an entire conversation unasked.

use crate::RoutingToken;
use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::path::Path;

pub struct ChatHistory {
    conn: Connection,
}

/// One persisted message, ready to render top-to-bottom.
pub struct StoredMessage {
    /// Row id — stable and monotonic per contact, so a UI can use it both
    /// as a list key and as a "load older than this" pagination cursor.
    pub id: i64,
    pub from_me: bool,
    pub text: String,
    pub timestamp_ms: i64,
}

impl ChatHistory {
    /// Open (creating if absent) the SQLCipher database at `db_path`, keyed
    /// by `vault_key`. Fails if the file exists and `vault_key` is wrong —
    /// SQLCipher itself would otherwise just hand back page-sized garbage
    /// on every query, so this forces one real read up front to fail fast
    /// and clearly instead.
    pub fn open(db_path: &Path, vault_key: &[u8; 32]) -> Result<Self> {
        let conn = Connection::open(db_path)
            .with_context(|| format!("opening chat history db at {}", db_path.display()))?;
        conn.pragma_update(None, "key", format!("x'{}'", hex::encode(vault_key)))?;
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .context("incorrect vault key, or corrupt chat history database")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_token TEXT NOT NULL,
                from_me INTEGER NOT NULL,
                body TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messages_contact ON messages(contact_token, id);",
        )?;
        Ok(Self { conn })
    }

    /// Record one message (sent or received) for `contact_token`, timestamped
    /// now. Returns the inserted row's id — the same id `recent` reports for
    /// this row — so a caller that just recorded a live message can label it
    /// with the exact id a later history fetch would also use for it,
    /// rather than a separate synthetic id that a naive merge could mistake
    /// for a second, different message.
    pub fn append(&self, contact_token: RoutingToken, from_me: bool, text: &str) -> Result<i64> {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        self.conn.execute(
            "INSERT INTO messages (contact_token, from_me, body, timestamp_ms) VALUES (?1, ?2, ?3, ?4)",
            params![hex::encode(contact_token), from_me as i64, text, timestamp_ms],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Permanently delete all locally-stored history with `contact_token`.
    /// Local-only, by the owning peer's own choice — never triggered by
    /// anything arriving over the network (see the `remove_contact` Tauri
    /// command's doc comment for why).
    pub fn delete_contact(&self, contact_token: RoutingToken) -> Result<()> {
        self.conn.execute(
            "DELETE FROM messages WHERE contact_token = ?1",
            params![hex::encode(contact_token)],
        )?;
        Ok(())
    }

    /// The most recent `limit` messages with `contact_token`, oldest first.
    pub fn recent(&self, contact_token: RoutingToken, limit: i64) -> Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, from_me, body, timestamp_ms FROM messages
             WHERE contact_token = ?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let mut rows = stmt.query(params![hex::encode(contact_token), limit])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(StoredMessage {
                id: row.get(0)?,
                from_me: row.get::<_, i64>(1)? != 0,
                text: row.get(2)?,
                timestamp_ms: row.get(3)?,
            });
        }
        out.reverse();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh scratch db path for one test, cleaned up on drop so tests
    /// never see each other's leftover files.
    struct ScratchDb(std::path::PathBuf);

    impl ScratchDb {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "e2e-messenger-history-test-{name}-{:x}.sqlite",
                rand_suffix()
            ));
            let _ = std::fs::remove_file(&path);
            Self(path)
        }
    }

    impl Drop for ScratchDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    #[test]
    fn test_append_and_recent_roundtrip() {
        let db = ScratchDb::new("roundtrip");
        let key = [7u8; 32];
        let history = ChatHistory::open(&db.0, &key).unwrap();
        let contact = [1u8; 16];

        history.append(contact, true, "hi").unwrap();
        history.append(contact, false, "hello back").unwrap();

        let msgs = history.recent(contact, 10).unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(msgs[0].from_me);
        assert_eq!(msgs[0].text, "hi");
        assert!(!msgs[1].from_me);
        assert_eq!(msgs[1].text, "hello back");
        // Oldest-first ordering, and ids strictly increasing.
        assert!(msgs[0].id < msgs[1].id);
    }

    #[test]
    fn test_history_survives_reopen_with_same_key() {
        let db = ScratchDb::new("reopen");
        let key = [9u8; 32];
        let contact = [2u8; 16];
        {
            let history = ChatHistory::open(&db.0, &key).unwrap();
            history.append(contact, true, "persisted?").unwrap();
        }
        let reopened = ChatHistory::open(&db.0, &key).unwrap();
        let msgs = reopened.recent(contact, 10).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].text, "persisted?");
    }

    #[test]
    fn test_wrong_key_fails_to_open() {
        let db = ScratchDb::new("wrongkey");
        {
            let history = ChatHistory::open(&db.0, &[1u8; 32]).unwrap();
            history.append([3u8; 16], true, "secret").unwrap();
        }
        assert!(ChatHistory::open(&db.0, &[2u8; 32]).is_err());
    }

    #[test]
    fn test_delete_contact_removes_only_that_contacts_messages() {
        let db = ScratchDb::new("delete_contact");
        let history = ChatHistory::open(&db.0, &[4u8; 32]).unwrap();
        let alice = [6u8; 16];
        let bob = [7u8; 16];
        history.append(alice, true, "to alice").unwrap();
        history.append(bob, true, "to bob").unwrap();

        history.delete_contact(alice).unwrap();

        assert_eq!(history.recent(alice, 10).unwrap().len(), 0);
        assert_eq!(history.recent(bob, 10).unwrap().len(), 1);
    }

    #[test]
    fn test_recent_scopes_to_contact_and_respects_limit() {
        let db = ScratchDb::new("scoped");
        let history = ChatHistory::open(&db.0, &[3u8; 32]).unwrap();
        let alice = [4u8; 16];
        let bob = [5u8; 16];

        history.append(alice, true, "to alice").unwrap();
        history.append(bob, true, "to bob").unwrap();
        for i in 0..5 {
            history.append(alice, false, &format!("msg {i}")).unwrap();
        }

        let alice_msgs = history.recent(alice, 3).unwrap();
        assert_eq!(alice_msgs.len(), 3);
        assert!(alice_msgs.iter().all(|m| m.text != "to bob"));

        let bob_msgs = history.recent(bob, 10).unwrap();
        assert_eq!(bob_msgs.len(), 1);
        assert_eq!(bob_msgs[0].text, "to bob");
    }
}
