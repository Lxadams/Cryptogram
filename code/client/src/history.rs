//! Local, per-identity chat history backed by SQLite + SQLCipher.
//!
//! Each peer keeps a full, independent copy of every conversation it has
//! ever had — there is no shared/synced history between peers (matches how
//! `identities/<pseudonym>/` already works: everything under it is local to
//! this machine and this identity only). The database lives right next to
//! `client_state.sqlite` under the same identity directory, keyed by the same
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
use std::collections::HashMap;
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
    /// For a message we sent, whether the relay confirmed it has it. `None`
    /// for received messages, and ones sent before this was tracked.
    pub status: Option<SendStatus>,
}

/// What became of a message we sent (see `Client::receipt_requests`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendStatus {
    /// Waiting for the relay to confirm it has enough of it.
    Sending,
    /// The relay has enough of it to deliver.
    Sent,
    /// The relay never confirmed it: too little of it got there, or the
    /// link went down first.
    Failed,
}

impl SendStatus {
    /// Its `status` column value. 0 is none (see `StoredMessage::status`).
    fn code(self) -> i64 {
        match self {
            SendStatus::Sending => 1,
            SendStatus::Sent => 2,
            SendStatus::Failed => 3,
        }
    }

    fn from_code(code: i64) -> Option<Self> {
        match code {
            1 => Some(SendStatus::Sending),
            2 => Some(SendStatus::Sent),
            3 => Some(SendStatus::Failed),
            _ => None,
        }
    }
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
                timestamp_ms INTEGER NOT NULL,
                status INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_messages_contact ON messages(contact_token, id);",
        )?;
        // Databases from before send statuses lack the column.
        let has_status: bool = conn.query_row(
            "SELECT count(*) FROM pragma_table_info('messages') WHERE name = 'status'",
            [],
            |row| row.get::<_, i64>(0).map(|n| n > 0),
        )?;
        if !has_status {
            conn.execute_batch(
                "ALTER TABLE messages ADD COLUMN status INTEGER NOT NULL DEFAULT 0;",
            )?;
        }
        // A message still sending when the app last closed can't be
        // confirmed now: what it would have been checked against is gone.
        conn.execute(
            "UPDATE messages SET status = ?1 WHERE status = ?2",
            params![SendStatus::Failed.code(), SendStatus::Sending.code()],
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
        self.append_at(contact_token, from_me, text, timestamp_ms)
    }

    /// `append`, timestamped `timestamp_ms` (Unix milliseconds), so a caller
    /// can show the message with the same time a later fetch will.
    pub fn append_at(
        &self,
        contact_token: RoutingToken,
        from_me: bool,
        text: &str,
        timestamp_ms: i64,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO messages (contact_token, from_me, body, timestamp_ms) VALUES (?1, ?2, ?3, ?4)",
            params![hex::encode(contact_token), from_me as i64, text, timestamp_ms],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Record what became of message `id`, one we sent.
    pub fn set_status(&self, id: i64, status: SendStatus) -> Result<()> {
        self.conn.execute(
            "UPDATE messages SET status = ?1 WHERE id = ?2",
            params![status.code(), id],
        )?;
        Ok(())
    }

    /// Message `id`: who it's with, and the message itself, if there's one
    /// with that id.
    pub fn message(&self, id: i64) -> Result<Option<(RoutingToken, StoredMessage)>> {
        let mut stmt = self.conn.prepare(
            "SELECT contact_token, from_me, body, timestamp_ms, status FROM messages WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let mut contact = [0u8; 16];
        hex::decode_to_slice(row.get::<_, String>(0)?, &mut contact)
            .context("malformed contact token in chat history")?;
        Ok(Some((
            contact,
            StoredMessage {
                id,
                from_me: row.get::<_, i64>(1)? != 0,
                text: row.get(2)?,
                timestamp_ms: row.get(3)?,
                status: SendStatus::from_code(row.get(4)?),
            },
        )))
    }

    /// Delete message `id`, as when it's been sent again as a new one.
    pub fn delete(&self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM messages WHERE id = ?1", params![id])?;
        Ok(())
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

    /// When the latest message (sent or received) with each contact we have
    /// any history with was recorded, in Unix milliseconds: what a contact
    /// list is ordered by, newest first.
    pub fn latest_per_contact(&self) -> Result<HashMap<RoutingToken, i64>> {
        let mut stmt = self.conn.prepare(
            "SELECT contact_token, MAX(timestamp_ms) FROM messages GROUP BY contact_token",
        )?;
        let mut rows = stmt.query([])?;
        let mut latest = HashMap::new();
        while let Some(row) = rows.next()? {
            let mut token = [0u8; 16];
            if hex::decode_to_slice(row.get::<_, String>(0)?, &mut token).is_ok() {
                latest.insert(token, row.get(1)?);
            }
        }
        Ok(latest)
    }

    /// The most recent `limit` messages with `contact_token`, oldest first.
    pub fn recent(&self, contact_token: RoutingToken, limit: i64) -> Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, from_me, body, timestamp_ms, status FROM messages
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
                status: SendStatus::from_code(row.get(4)?),
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
    fn test_one_message_can_be_looked_up_and_deleted() {
        let db = ScratchDb::new("one-message");
        let history = ChatHistory::open(&db.0, &[5u8; 32]).unwrap();
        let (alice, bob) = ([1u8; 16], [2u8; 16]);
        let first = history.append_at(alice, true, "first", 100).unwrap();
        let second = history.append_at(bob, false, "second", 200).unwrap();

        let (contact, message) = history.message(first).unwrap().unwrap();
        assert_eq!(contact, alice);
        assert_eq!((message.text.as_str(), message.from_me), ("first", true));
        history.delete(first).unwrap();
        assert!(history.message(first).unwrap().is_none());
        assert_eq!(history.message(second).unwrap().unwrap().0, bob);
        assert!(history.recent(alice, 10).unwrap().is_empty());
    }

    #[test]
    fn test_latest_per_contact_is_each_contacts_newest_message() {
        let db = ScratchDb::new("latest");
        let history = ChatHistory::open(&db.0, &[6u8; 32]).unwrap();
        let (alice, bob, carol) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        history.append_at(alice, true, "a1", 100).unwrap();
        history.append_at(bob, false, "b1", 300).unwrap();
        history.append_at(alice, false, "a2", 200).unwrap();

        let latest = history.latest_per_contact().unwrap();
        assert_eq!(latest.get(&alice), Some(&200));
        assert_eq!(latest.get(&bob), Some(&300));
        assert_eq!(latest.get(&carol), None, "no history, no entry");
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
    fn test_send_statuses_are_kept_and_a_send_cut_short_has_failed() {
        let db = ScratchDb::new("statuses");
        let key = [8u8; 32];
        let contact = [2u8; 16];
        let (sent, sending, received) = {
            let history = ChatHistory::open(&db.0, &key).unwrap();
            let sent = history.append_at(contact, true, "sent", 1000).unwrap();
            history.set_status(sent, SendStatus::Sent).unwrap();
            let sending = history.append(contact, true, "sending").unwrap();
            history.set_status(sending, SendStatus::Sending).unwrap();
            let received = history.append(contact, false, "received").unwrap();
            let msgs = history.recent(contact, 10).unwrap();
            assert_eq!(msgs[0].timestamp_ms, 1000);
            assert_eq!(msgs[1].status, Some(SendStatus::Sending));
            (sent, sending, received)
        };

        // Reopened, as when the app starts again: the one still sending
        // can't be confirmed any more.
        let reopened = ChatHistory::open(&db.0, &key).unwrap();
        let statuses: Vec<_> = reopened
            .recent(contact, 10)
            .unwrap()
            .into_iter()
            .map(|m| (m.id, m.status))
            .collect();
        assert_eq!(
            statuses,
            [
                (sent, Some(SendStatus::Sent)),
                (sending, Some(SendStatus::Failed)),
                (received, None),
            ]
        );
    }

    #[test]
    fn test_a_database_from_before_statuses_gains_them() {
        let db = ScratchDb::new("old_schema");
        let key = [5u8; 32];
        {
            let conn = Connection::open(&db.0).unwrap();
            conn.pragma_update(None, "key", format!("x'{}'", hex::encode(key)))
                .unwrap();
            conn.execute_batch(
                "CREATE TABLE messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    contact_token TEXT NOT NULL,
                    from_me INTEGER NOT NULL,
                    body TEXT NOT NULL,
                    timestamp_ms INTEGER NOT NULL
                );
                INSERT INTO messages (contact_token, from_me, body, timestamp_ms)
                    VALUES ('01010101010101010101010101010101', 1, 'old', 5);",
            )
            .unwrap();
        }
        let history = ChatHistory::open(&db.0, &key).unwrap();
        let contact = [1u8; 16];
        let msgs = history.recent(contact, 10).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].status, None);
        let id = history.append(contact, true, "new").unwrap();
        history.set_status(id, SendStatus::Sent).unwrap();
        assert_eq!(
            history.recent(contact, 10).unwrap()[1].status,
            Some(SendStatus::Sent)
        );
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
