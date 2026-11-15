// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The listener table a hot upgrade hands from the outgoing supervisor to
//! the incoming one over `transfer.sock` (Story 12.11 D-d).
//!
//! # Two formats on one socket
//!
//! **Legacy**, the fork's `Fds::send_to_sock` and every release up to
//! 1.10.x: one `sendmsg`, keys space-joined in the payload, every
//! descriptor in one `SCM_RIGHTS` header. Its receiver reads 2,048 bytes
//! of keys and makes room for 32 descriptors; past either, keys arrive
//! truncated or descriptors are dropped by the kernel (`MSG_CTRUNC`).
//!
//! **Chunked**, `lorica-fds/2`: a header line `lorica-fds/2 <entries>\n`
//! carrying no descriptor, then chunks of at most [`CHUNK_MAX_FDS`]
//! descriptors whose keys fit [`CHUNK_MAX_KEY_BYTES`]. A chunk is one
//! frame, `[u32 BE body length][body]`, the body a sequence of
//! `[u16 BE key length][key]`, the i-th key naming the i-th descriptor.
//! The receiver acknowledges the header and every chunk with one byte,
//! and the sender waits for it before sending anything more: a unix
//! stream socket attaches `SCM_RIGHTS` to bytes, not to messages, so
//! without the wait two chunks could be read as one and descriptors
//! paired with the wrong keys.
//!
//! # Compatibility, both ways
//!
//! The sender uses the legacy message whenever the table fits it, so a
//! node whose table fits (every node without streams) still hot-downgrades
//! to a 1.10.x binary. A table that does not fit is sent chunked; a 1.10.x
//! receiver then fails, the new process never signals ready and the
//! upgrade rolls back. The receiver reads the first message and tells the
//! two apart by the format token.
//!
//! # Failure closes everything received
//!
//! Every received descriptor is owned from the moment it arrives, so any
//! framing error, short chunk or count mismatch closes all of them and
//! fails the pull.

use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use lorica_core::server::Fds;
use lorica_worker::fd_passing::{self, ReceivedRights};

/// First bytes of a chunked transfer's header line.
const FORMAT_TOKEN: &str = "lorica-fds/2";

/// Most descriptors one chunk carries.
pub(crate) const CHUNK_MAX_FDS: usize = 32;

/// Most bytes of one chunk's body: its keys with their length prefixes.
pub(crate) const CHUNK_MAX_KEY_BYTES: usize = 8 * 1024;

const _: () = assert!(
    CHUNK_MAX_FDS <= fd_passing::MAX_FDS,
    "a chunk must fit the control buffer of one receive"
);

/// A chunk frame: the body length, then the body.
const FRAME_MAX_LEN: usize = 4 + CHUNK_MAX_KEY_BYTES;

/// Most descriptors the legacy receiver makes room for.
const LEGACY_MAX_FDS: usize = 32;

/// Size of the legacy receiver's key buffer, which the legacy sender
/// fills without checking.
const LEGACY_KEYS_MAX_BYTES: usize = 2048;

/// The byte a receiver answers the header and each chunk with.
const ACK: u8 = 0x06;

/// Longest header line accepted: the token, a space, a `usize` and `\n`.
const HEADER_MAX_LEN: usize = FORMAT_TOKEN.len() + 1 + 20 + 1;

/// How long either side waits for the other to show up on the socket,
/// the budget the fork's sender and receiver have always had.
const RENDEZVOUS_DEADLINE: Duration = Duration::from_secs(6);

/// Poll interval while waiting for the other side to show up.
const RENDEZVOUS_POLL: Duration = Duration::from_millis(50);

/// How long a connected side waits on one read or one write.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether `keys` fit the legacy single message: at most
/// [`LEGACY_MAX_FDS`] of them, space-joined within
/// [`LEGACY_KEYS_MAX_BYTES`], none empty or holding the whitespace that
/// separates them.
fn fits_legacy_message(keys: &[String]) -> bool {
    let joined_len = keys
        .iter()
        .map(|k| k.len() + 1)
        .sum::<usize>()
        .saturating_sub(1);
    keys.len() <= LEGACY_MAX_FDS
        && joined_len <= LEGACY_KEYS_MAX_BYTES
        && keys
            .iter()
            .all(|k| !k.is_empty() && !k.bytes().any(|b| b.is_ascii_whitespace()))
}

/// Send `table` to the receiver listening on `path` (BLOCKING): the
/// legacy single message when it fits, the chunked transfer otherwise.
pub(crate) fn send_table(table: &Fds, path: &Path) -> Result<(), String> {
    let (keys, fds) = table.serialize();
    if fits_legacy_message(&keys) {
        let path_str = path.to_string_lossy();
        return table
            .send_to_sock(path_str.as_ref())
            .map(|_sent| ())
            .map_err(|e| format!("legacy transfer failed: {e}"));
    }
    send_chunked(&keys, &fds, path)
}

/// The chunks a table is sent in, as ranges of its entries: at most
/// [`CHUNK_MAX_FDS`] entries each, keys within [`CHUNK_MAX_KEY_BYTES`].
fn plan_chunks(keys: &[String]) -> Result<Vec<std::ops::Range<usize>>, String> {
    let mut chunks = Vec::new();
    let (mut start, mut body_len) = (0, 0);
    for (i, key) in keys.iter().enumerate() {
        let entry_len = 2 + key.len();
        if key.is_empty() || entry_len > CHUNK_MAX_KEY_BYTES || key.len() > usize::from(u16::MAX) {
            return Err(format!(
                "listener key of {} bytes cannot be transferred",
                key.len()
            ));
        }
        if i - start == CHUNK_MAX_FDS || body_len + entry_len > CHUNK_MAX_KEY_BYTES {
            chunks.push(start..i);
            (start, body_len) = (i, 0);
        }
        body_len += entry_len;
    }
    if start < keys.len() {
        chunks.push(start..keys.len());
    }
    Ok(chunks)
}

fn encode_chunk(keys: &[String]) -> Vec<u8> {
    let body_len: usize = keys.iter().map(|k| 2 + k.len()).sum();
    let mut frame = Vec::with_capacity(4 + body_len);
    frame.extend_from_slice(&(body_len as u32).to_be_bytes());
    for key in keys {
        frame.extend_from_slice(&(key.len() as u16).to_be_bytes());
        frame.extend_from_slice(key.as_bytes());
    }
    frame
}

fn send_chunked(keys: &[String], fds: &[RawFd], path: &Path) -> Result<(), String> {
    let chunks = plan_chunks(keys)?;
    let mut conn = connect_with_retry(path)?;
    conn.write_all(format!("{FORMAT_TOKEN} {}\n", keys.len()).as_bytes())
        .map_err(|e| format!("sending the transfer header failed: {e}"))?;
    await_ack(&mut conn, "header")?;
    for (n, range) in chunks.into_iter().enumerate() {
        let frame = encode_chunk(&keys[range.clone()]);
        let sent = fd_passing::send_with_rights(conn.as_raw_fd(), &frame, &fds[range])
            .map_err(|e| format!("sending chunk {n} failed: {e}"))?;
        conn.write_all(&frame[sent..])
            .map_err(|e| format!("sending the rest of chunk {n} failed: {e}"))?;
        await_ack(&mut conn, "chunk")?;
    }
    Ok(())
}

fn await_ack(conn: &mut UnixStream, what: &str) -> Result<(), String> {
    let mut ack = [0u8; 1];
    conn.read_exact(&mut ack)
        .map_err(|e| format!("no acknowledgement of the {what}: {e}"))?;
    if ack[0] != ACK {
        return Err(format!("unexpected acknowledgement byte {:#04x}", ack[0]));
    }
    Ok(())
}

fn connect_with_retry(path: &Path) -> Result<UnixStream, String> {
    let start = Instant::now();
    loop {
        match UnixStream::connect(path) {
            Ok(conn) => {
                conn.set_read_timeout(Some(IO_TIMEOUT))
                    .and_then(|()| conn.set_write_timeout(Some(IO_TIMEOUT)))
                    .map_err(|e| format!("cannot set transfer socket timeouts: {e}"))?;
                return Ok(conn);
            }
            // Not bound yet, bound but not listening, or not yet chmod'ed:
            // the receiver is still starting.
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::NotFound
                        | ErrorKind::ConnectionRefused
                        | ErrorKind::PermissionDenied
                ) && start.elapsed() < RENDEZVOUS_DEADLINE =>
            {
                std::thread::sleep(RENDEZVOUS_POLL);
            }
            Err(e) => return Err(format!("cannot connect to {}: {e}", path.display())),
        }
    }
}

/// Removes the transfer socket's path on every way out of the receive.
struct SocketPath<'a>(&'a Path);

impl Drop for SocketPath<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0);
    }
}

/// Listen on `path` for one sender and receive its table (BLOCKING), in
/// either format. Every descriptor is returned owned; on any error every
/// descriptor received so far is closed.
pub(crate) fn receive_table(path: &Path) -> Result<Vec<(String, OwnedFd)>, String> {
    let _ = std::fs::remove_file(path);
    let listener =
        UnixListener::bind(path).map_err(|e| format!("cannot bind {}: {e}", path.display()))?;
    let _cleanup = SocketPath(path);
    // Owner-only: the socket hands over live listening sockets (audit L1).
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("cannot restrict {}: {e}", path.display()))?;
    let conn = accept_with_retry(&listener, path)?;
    drop(listener);
    receive_from(conn)
}

fn accept_with_retry(listener: &UnixListener, path: &Path) -> Result<UnixStream, String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("cannot poll {}: {e}", path.display()))?;
    let start = Instant::now();
    loop {
        match listener.accept() {
            Ok((conn, _)) => {
                conn.set_nonblocking(false)
                    .and_then(|()| conn.set_read_timeout(Some(IO_TIMEOUT)))
                    .and_then(|()| conn.set_write_timeout(Some(IO_TIMEOUT)))
                    .map_err(|e| format!("cannot configure the transfer connection: {e}"))?;
                return Ok(conn);
            }
            Err(e)
                if e.kind() == ErrorKind::WouldBlock && start.elapsed() < RENDEZVOUS_DEADLINE =>
            {
                std::thread::sleep(RENDEZVOUS_POLL);
            }
            Err(e) => {
                return Err(format!(
                    "no outgoing supervisor connected to {}: {e}",
                    path.display()
                ))
            }
        }
    }
}

fn recv(conn: &UnixStream, buf: &mut [u8]) -> Result<ReceivedRights, String> {
    let received = fd_passing::recv_with_rights_cloexec(conn.as_raw_fd(), buf)
        .map_err(|e| format!("transfer read failed: {e}"))?;
    if received.truncated {
        return Err(format!(
            "transfer message truncated ({} descriptors kept, all closed)",
            received.fds.len()
        ));
    }
    Ok(received)
}

fn receive_from(mut conn: UnixStream) -> Result<Vec<(String, OwnedFd)>, String> {
    let mut buf = vec![0u8; FRAME_MAX_LEN];
    let first = recv(&conn, &mut buf)?;
    if first.bytes == 0 && first.fds.is_empty() {
        return Err("the outgoing supervisor closed the transfer without sending".to_string());
    }
    let payload = &buf[..first.bytes];
    if !payload.starts_with(format!("{FORMAT_TOKEN} ").as_bytes()) {
        return decode_legacy(payload, first.fds);
    }
    if !first.fds.is_empty() {
        return Err("the transfer header carries descriptors".to_string());
    }
    let entries = read_header(&mut conn, payload.to_vec())?;
    conn.write_all(&[ACK])
        .map_err(|e| format!("acknowledging the header failed: {e}"))?;

    let mut table: Vec<(String, OwnedFd)> = Vec::new();
    while table.len() < entries {
        let (keys, fds) = read_chunk(&conn, &mut buf)?;
        if fds.is_empty() || fds.len() > CHUNK_MAX_FDS || keys.len() != fds.len() {
            return Err(format!(
                "chunk carries {} keys and {} descriptors",
                keys.len(),
                fds.len()
            ));
        }
        if table.len() + fds.len() > entries {
            return Err(format!(
                "chunks carry more than the {entries} entries the header announced"
            ));
        }
        table.extend(keys.into_iter().zip(fds));
        conn.write_all(&[ACK])
            .map_err(|e| format!("acknowledging a chunk failed: {e}"))?;
    }
    Ok(table)
}

/// Read the rest of the header line, if the first read did not hold all
/// of it, and parse its entry count.
fn read_header(conn: &mut UnixStream, mut line: Vec<u8>) -> Result<usize, String> {
    while !line.contains(&b'\n') {
        if line.len() >= HEADER_MAX_LEN {
            return Err("transfer header too long".to_string());
        }
        let mut byte = [0u8; 1];
        conn.read_exact(&mut byte)
            .map_err(|e| format!("transfer header cut short: {e}"))?;
        line.push(byte[0]);
    }
    let text = std::str::from_utf8(&line)
        .ok()
        .and_then(|l| l.strip_prefix(FORMAT_TOKEN))
        .and_then(|l| l.strip_prefix(' '))
        .and_then(|l| l.strip_suffix('\n'))
        .ok_or_else(|| "malformed transfer header".to_string())?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("malformed transfer header".to_string());
    }
    text.parse()
        .map_err(|_| "malformed transfer header".to_string())
}

/// Read one chunk frame, with every descriptor that came with it.
fn read_chunk(conn: &UnixStream, buf: &mut [u8]) -> Result<(Vec<String>, Vec<OwnedFd>), String> {
    let mut fds: Vec<OwnedFd> = Vec::new();
    let mut filled = 0;
    loop {
        if filled >= 4 {
            let body_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if body_len > CHUNK_MAX_KEY_BYTES {
                return Err(format!("chunk body of {body_len} bytes is too long"));
            }
            match filled.cmp(&(4 + body_len)) {
                std::cmp::Ordering::Equal => return Ok((decode_keys(&buf[4..filled])?, fds)),
                std::cmp::Ordering::Greater => {
                    return Err("bytes past the end of a chunk".to_string())
                }
                std::cmp::Ordering::Less => {}
            }
        }
        let received = recv(conn, &mut buf[filled..])?;
        fds.extend(received.fds);
        if received.bytes == 0 {
            return Err(format!(
                "the outgoing supervisor closed the transfer in the middle of a chunk \
                 ({} descriptors received with it, all closed)",
                fds.len()
            ));
        }
        filled += received.bytes;
    }
}

fn decode_keys(mut body: &[u8]) -> Result<Vec<String>, String> {
    let mut keys = Vec::new();
    while !body.is_empty() {
        let (len, rest) = body
            .split_first_chunk::<2>()
            .ok_or_else(|| "chunk body cut inside a key length".to_string())?;
        let len = usize::from(u16::from_be_bytes(*len));
        if len == 0 || rest.len() < len {
            return Err("chunk body cut inside a key".to_string());
        }
        let key =
            std::str::from_utf8(&rest[..len]).map_err(|_| "chunk key is not UTF-8".to_string())?;
        keys.push(key.to_string());
        body = &rest[len..];
    }
    Ok(keys)
}

/// Parse the legacy single message the way the fork's receiver does,
/// failing where it would assert.
fn decode_legacy(payload: &[u8], fds: Vec<OwnedFd>) -> Result<Vec<(String, OwnedFd)>, String> {
    let keys: Vec<String> = std::str::from_utf8(payload)
        .map_err(|_| "legacy transfer keys are not UTF-8".to_string())?
        .split_ascii_whitespace()
        .map(String::from)
        .collect();
    if keys.len() != fds.len() {
        return Err(format!(
            "legacy transfer carries {} keys and {} descriptors",
            keys.len(),
            fds.len()
        ));
    }
    Ok(keys.into_iter().zip(fds).collect())
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::path::{Path, PathBuf};

    /// Open descriptors standing in for listening sockets: one file per
    /// table entry, so a received descriptor is matched to the entry it
    /// was sent for through `/proc/self/fd`, not merely counted.
    pub(crate) struct DescriptorFixture {
        dir: tempfile::TempDir,
        files: Vec<(PathBuf, std::fs::File)>,
    }

    impl DescriptorFixture {
        pub(crate) fn new(count: usize) -> Self {
            let dir = tempfile::tempdir().expect("test descriptor dir");
            let files = (0..count)
                .map(|i| {
                    let path = dir.path().join(format!("fd-{i}"));
                    let file = std::fs::File::create(&path).expect("test descriptor file");
                    (path, file)
                })
                .collect();
            Self { dir, files }
        }

        pub(crate) fn fd(&self, i: usize) -> RawFd {
            self.files[i].1.as_raw_fd()
        }

        pub(crate) fn path(&self, i: usize) -> &Path {
            &self.files[i].0
        }

        /// How many descriptors of this process name one of the
        /// fixture's files. Tests run in parallel, so a global count of
        /// open descriptors would be noise; these files are this
        /// fixture's alone.
        pub(crate) fn open_descriptors(&self) -> usize {
            std::fs::read_dir("/proc/self/fd")
                .expect("procfs")
                .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
                .filter(|target| target.starts_with(self.dir.path()))
                .count()
        }
    }

    pub(crate) fn path_of(fd: RawFd) -> PathBuf {
        std::fs::read_link(format!("/proc/self/fd/{fd}")).expect("received descriptor is open")
    }

    pub(crate) fn close_received(fd: RawFd) {
        // SAFETY: received over SCM_RIGHTS by the pull under test and
        // owned by nothing else in this test.
        drop(unsafe { OwnedFd::from_raw_fd(fd) });
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{path_of, DescriptorFixture};
    use super::*;

    fn socket_in(dir: &tempfile::TempDir) -> std::path::PathBuf {
        dir.path().join("transfer.sock")
    }

    fn table_of(fixture: &DescriptorFixture, keys: &[String]) -> Fds {
        let mut table = Fds::new();
        for (i, key) in keys.iter().enumerate() {
            table.add(key.clone(), fixture.fd(i));
        }
        table
    }

    fn short_keys(count: usize) -> Vec<String> {
        (0..count)
            .map(|i| format!("192.0.2.10:{}", 10_000 + i))
            .collect()
    }

    fn assert_received(
        fixture: &DescriptorFixture,
        keys: &[String],
        received: &[(String, OwnedFd)],
    ) {
        assert_eq!(received.len(), keys.len());
        for (key, fd) in received {
            let i = keys
                .iter()
                .position(|k| k == key)
                .unwrap_or_else(|| panic!("received key `{key}` was never sent"));
            assert_eq!(
                path_of(fd.as_raw_fd()),
                fixture.path(i),
                "descriptor of `{key}`"
            );
        }
    }

    #[test]
    fn the_legacy_limits_decide_the_format() {
        assert!(fits_legacy_message(&short_keys(32)));
        assert!(!fits_legacy_message(&short_keys(33)));
        // Exactly the legacy buffer: 1,023 and 1,024 bytes and a space.
        assert!(fits_legacy_message(&["a".repeat(1_023), "b".repeat(1_024)]));
        assert!(!fits_legacy_message(&[
            "a".repeat(1_024),
            "b".repeat(1_024)
        ]));
        // A key the space-joined format cannot carry goes chunked.
        assert!(!fits_legacy_message(&["has space".to_string()]));
        assert!(!fits_legacy_message(&[String::new()]));
    }

    #[test]
    fn chunks_hold_at_most_32_descriptors_and_8_kib_of_keys() {
        let ranges = plan_chunks(&short_keys(65)).expect("plan");
        assert_eq!(ranges, vec![0..32, 32..64, 64..65]);

        // 3,000-byte keys: two fill a chunk's 8 KiB, the third starts the next.
        let long: Vec<String> = (0..5)
            .map(|i| format!("{i}{}", "k".repeat(2_999)))
            .collect();
        let ranges = plan_chunks(&long).expect("plan");
        assert_eq!(ranges, vec![0..2, 2..4, 4..5]);
        for range in ranges {
            assert!(encode_chunk(&long[range]).len() <= FRAME_MAX_LEN);
        }

        assert!(plan_chunks(&["k".repeat(CHUNK_MAX_KEY_BYTES)]).is_err());
    }

    #[test]
    fn a_table_that_fits_is_read_by_the_legacy_receiver() {
        // Downgrade compatibility: a 1.10.x binary pulls with the fork's
        // `get_from_sock`, which would assert on the chunked header.
        let fixture = DescriptorFixture::new(32);
        let keys = short_keys(32);
        let table = table_of(&fixture, &keys);
        let dir = tempfile::tempdir().expect("test dir");
        let path = socket_in(&dir);
        let receiver_path = path.to_string_lossy().into_owned();
        let receiver = std::thread::spawn(move || {
            let mut legacy = Fds::new();
            legacy
                .get_from_sock(receiver_path.as_str())
                .map(|()| legacy)
        });
        send_table(&table, &path).expect("send");
        let legacy = receiver
            .join()
            .expect("the legacy receiver does not panic")
            .expect("the legacy receiver pulls");
        let (got_keys, got_fds) = legacy.serialize();
        let received: Vec<(String, OwnedFd)> = got_keys
            .into_iter()
            .zip(got_fds)
            // SAFETY: received over SCM_RIGHTS by `get_from_sock` above
            // and owned by nothing else.
            .map(|(k, fd)| {
                (k, unsafe {
                    <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd)
                })
            })
            .collect();
        assert_received(&fixture, &keys, &received);
    }

    #[test]
    fn a_legacy_message_is_read_by_the_new_receiver() {
        // Upgrade from 1.10.x: the outgoing binary sends the fork's
        // single message.
        let fixture = DescriptorFixture::new(5);
        let keys = short_keys(5);
        let table = table_of(&fixture, &keys);
        let dir = tempfile::tempdir().expect("test dir");
        let path = socket_in(&dir);
        let receiver_path = path.clone();
        let receiver = std::thread::spawn(move || receive_table(&receiver_path));
        table
            .send_to_sock(path.to_string_lossy().as_ref())
            .expect("legacy send");
        let received = receiver.join().expect("no panic").expect("receive");
        assert_received(&fixture, &keys, &received);
        assert!(!path.exists(), "the transfer socket is removed after use");
    }

    #[test]
    fn a_chunked_table_fails_against_the_legacy_receiver_without_hanging() {
        // D-d's safe failure: a 1.10.x incoming binary cannot read a
        // table past the legacy limits, and the outgoing side gives up
        // instead of waiting for an acknowledgement that never comes.
        let fixture = DescriptorFixture::new(33);
        let table = table_of(&fixture, &short_keys(33));
        let dir = tempfile::tempdir().expect("test dir");
        let path = socket_in(&dir);
        let receiver_path = path.to_string_lossy().into_owned();
        let receiver = std::thread::spawn(move || {
            let mut legacy = Fds::new();
            legacy.get_from_sock(receiver_path.as_str())
        });
        let err = send_table(&table, &path).expect_err("the legacy receiver cannot take it");
        assert!(err.contains("acknowledgement"), "{err}");
        let _ = receiver.join();
    }

    /// Play the outgoing side by hand: send `header`, then each chunk as
    /// one frame and its descriptors, waiting for every acknowledgement
    /// but the last chunk's, then hang up.
    fn send_by_hand(path: &Path, header: &str, chunks: &[(Vec<u8>, Vec<RawFd>)]) {
        let mut conn = connect_with_retry(path).expect("connect");
        conn.write_all(header.as_bytes()).expect("header");
        if await_ack(&mut conn, "header").is_err() {
            return;
        }
        for (n, (frame, fds)) in chunks.iter().enumerate() {
            fd_passing::send_with_rights(conn.as_raw_fd(), frame, fds).expect("chunk");
            if n + 1 == chunks.len() || await_ack(&mut conn, "chunk").is_err() {
                return;
            }
        }
    }

    fn receive_from_hand_sender(
        header: &str,
        chunks: Vec<(Vec<u8>, Vec<RawFd>)>,
    ) -> Result<Vec<(String, OwnedFd)>, String> {
        let dir = tempfile::tempdir().expect("test dir");
        let path = socket_in(&dir);
        let receiver_path = path.clone();
        let receiver = std::thread::spawn(move || receive_table(&receiver_path));
        send_by_hand(&path, header, &chunks);
        receiver.join().expect("the receiver does not panic")
    }

    #[test]
    fn a_truncated_chunk_fails_the_pull_and_leaks_no_descriptor() {
        let fixture = DescriptorFixture::new(3);
        let keys = short_keys(3);
        let mut frame = encode_chunk(&keys);
        frame.truncate(frame.len() - 5);
        let fds = (0..3).map(|i| fixture.fd(i)).collect();
        let err = receive_from_hand_sender("lorica-fds/2 3\n", vec![(frame, fds)])
            .expect_err("a short chunk fails the pull");
        assert!(err.contains("middle of a chunk"), "{err}");
        assert_eq!(
            fixture.open_descriptors(),
            3,
            "only the sender's own descriptors remain"
        );
    }

    #[test]
    fn a_count_mismatch_fails_the_pull_and_leaks_no_descriptor() {
        let fixture = DescriptorFixture::new(5);
        let keys = short_keys(5);

        // Two keys for three descriptors.
        let fds = (0..3).map(|i| fixture.fd(i)).collect();
        let err =
            receive_from_hand_sender("lorica-fds/2 3\n", vec![(encode_chunk(&keys[..2]), fds)])
                .expect_err("keys and descriptors disagree");
        assert!(err.contains("2 keys and 3 descriptors"), "{err}");
        assert_eq!(fixture.open_descriptors(), 5);

        // A complete first chunk, then the sender hangs up short of the
        // five entries its header announced: the first chunk's
        // descriptors are closed too. Whether the hang-up is seen at the
        // acknowledgement or at the next read is a race; the outcome is
        // the same.
        let fds = (0..2).map(|i| fixture.fd(i)).collect();
        receive_from_hand_sender("lorica-fds/2 5\n", vec![(encode_chunk(&keys[..2]), fds)])
            .expect_err("fewer entries than announced");
        assert_eq!(fixture.open_descriptors(), 5);

        // More entries than announced.
        let fds = (0..3).map(|i| fixture.fd(i)).collect();
        let err =
            receive_from_hand_sender("lorica-fds/2 2\n", vec![(encode_chunk(&keys[..3]), fds)])
                .expect_err("more entries than announced");
        assert!(err.contains("more than the 2 entries"), "{err}");
        assert_eq!(fixture.open_descriptors(), 5);
    }

    #[test]
    fn a_legacy_count_mismatch_fails_the_pull_and_leaks_no_descriptor() {
        let fixture = DescriptorFixture::new(3);
        let dir = tempfile::tempdir().expect("test dir");
        let path = socket_in(&dir);
        let receiver_path = path.clone();
        let receiver = std::thread::spawn(move || receive_table(&receiver_path));
        let conn = connect_with_retry(&path).expect("connect");
        let fds: Vec<RawFd> = (0..3).map(|i| fixture.fd(i)).collect();
        fd_passing::send_with_rights(conn.as_raw_fd(), b"192.0.2.10:1 192.0.2.10:2", &fds)
            .expect("send");
        drop(conn);
        let err = receiver
            .join()
            .expect("no panic")
            .expect_err("two keys for three descriptors");
        assert!(err.contains("2 keys and 3 descriptors"), "{err}");
        assert_eq!(fixture.open_descriptors(), 3);
    }

    #[test]
    fn a_malformed_header_fails_the_pull() {
        for header in ["lorica-fds/2 \n", "lorica-fds/2 -1\n", "lorica-fds/2 1x\n"] {
            let err = receive_from_hand_sender(header, Vec::new())
                .expect_err("a malformed header fails the pull");
            assert!(
                err.contains("malformed transfer header"),
                "{header:?}: {err}"
            );
        }
    }
}
