//! CTAPHID transport (FIDO CTAP 2.2, section 11.2): 64-byte HID reports carrying framed messages
//! on logical channels. [`Transport`] is a pure state machine over reports and the current time;
//! [`run`] is the I/O loop that keeps KEEPALIVEs flowing while a handler is busy.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const REPORT_SIZE: usize = 64;
pub type Report = [u8; REPORT_SIZE];
pub const BROADCAST_CID: u32 = 0xffff_ffff;
pub const INIT_DATA_SIZE: usize = REPORT_SIZE - 7;
pub const CONT_DATA_SIZE: usize = REPORT_SIZE - 5;
pub const MAX_SEQ: u8 = 0x7f;
/// Largest message: one initialization packet plus 128 continuation packets (7609 bytes).
pub const MAX_MESSAGE_SIZE: usize = INIT_DATA_SIZE + (MAX_SEQ as usize + 1) * CONT_DATA_SIZE;
pub const PROTOCOL_VERSION: u8 = 2;
/// Channels remembered at once; allocating more forgets the oldest one that is not in use.
pub const MAX_CHANNELS: usize = 64;
/// Request threads alive at once, finished-but-cancelled ones included.
pub const MAX_WORKERS: usize = 4;

const TYPE_INIT: u8 = 0x80;

pub mod cmd {
    pub const PING: u8 = 0x01;
    pub const MSG: u8 = 0x03;
    pub const LOCK: u8 = 0x04;
    pub const INIT: u8 = 0x06;
    pub const WINK: u8 = 0x08;
    pub const CBOR: u8 = 0x10;
    pub const CANCEL: u8 = 0x11;
    pub const KEEPALIVE: u8 = 0x3b;
    pub const ERROR: u8 = 0x3f;
}

pub mod err {
    pub const INVALID_CMD: u8 = 0x01;
    pub const INVALID_PAR: u8 = 0x02;
    pub const INVALID_LEN: u8 = 0x03;
    pub const INVALID_SEQ: u8 = 0x04;
    pub const MSG_TIMEOUT: u8 = 0x05;
    pub const CHANNEL_BUSY: u8 = 0x06;
    pub const LOCK_REQUIRED: u8 = 0x0a;
    pub const INVALID_CHANNEL: u8 = 0x0b;
    pub const OTHER: u8 = 0x7f;
}

pub mod capability {
    pub const WINK: u8 = 0x01;
    pub const CBOR: u8 = 0x04;
    /// Set when CTAPHID_MSG (U2F) is not implemented.
    pub const NMSG: u8 = 0x08;
}

pub mod ctap2_status {
    pub const ERR_OTHER: u8 = 0x7f;
    pub const ERR_KEEPALIVE_CANCEL: u8 = 0x2d;
    pub const ERR_USER_ACTION_TIMEOUT: u8 = 0x2f;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeepaliveStatus {
    Processing = 1,
    UpNeeded = 2,
}

impl KeepaliveStatus {
    fn from_u8(v: u8) -> Self {
        if v == Self::UpNeeded as u8 {
            Self::UpNeeded
        } else {
            Self::Processing
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packet<'a> {
    Init {
        cid: u32,
        cmd: u8,
        bcnt: u16,
        data: &'a [u8],
    },
    Cont {
        cid: u32,
        seq: u8,
        data: &'a [u8],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadReportSize(pub usize);

impl fmt::Display for BadReportSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HID report of {} bytes, expected {REPORT_SIZE}", self.0)
    }
}

impl std::error::Error for BadReportSize {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageTooLarge(pub usize);

impl fmt::Display for MessageTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CTAPHID message of {} bytes exceeds {MAX_MESSAGE_SIZE}",
            self.0
        )
    }
}

impl std::error::Error for MessageTooLarge {}

/// The data slice of an initialization packet is always the full 57 bytes; the caller trims it to `bcnt`.
pub fn parse_packet(report: &[u8]) -> Result<Packet<'_>, BadReportSize> {
    let bad = BadReportSize(report.len());
    if report.len() != REPORT_SIZE {
        return Err(bad);
    }
    let Some((cid, [kind, rest @ ..])) = report.split_first_chunk::<4>() else {
        return Err(bad);
    };
    let cid = u32::from_be_bytes(*cid);
    if kind & TYPE_INIT == 0 {
        return Ok(Packet::Cont {
            cid,
            seq: *kind,
            data: rest,
        });
    }
    let (bcnt, data) = rest.split_first_chunk::<2>().ok_or(bad)?;
    Ok(Packet::Init {
        cid,
        cmd: kind & !TYPE_INIT,
        bcnt: u16::from_be_bytes(*bcnt),
        data,
    })
}

pub fn build_message(
    cid: u32,
    command: u8,
    payload: &[u8],
) -> Result<Vec<Report>, MessageTooLarge> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(MessageTooLarge(payload.len()));
    }
    let bcnt = u16::try_from(payload.len()).map_err(|_| MessageTooLarge(payload.len()))?;
    let cid = cid.to_be_bytes();
    let mut out = Vec::new();

    let mut first: Report = [0; REPORT_SIZE];
    write_into(&mut first, 0, &cid);
    write_into(&mut first, 4, &[TYPE_INIT | command]);
    write_into(&mut first, 5, &bcnt.to_be_bytes());
    let (head, mut rest) = payload.split_at(payload.len().min(INIT_DATA_SIZE));
    write_into(&mut first, 7, head);
    out.push(first);

    let mut seq: u8 = 0;
    while !rest.is_empty() {
        let (chunk, tail) = rest.split_at(rest.len().min(CONT_DATA_SIZE));
        let mut packet: Report = [0; REPORT_SIZE];
        write_into(&mut packet, 0, &cid);
        write_into(&mut packet, 4, &[seq]);
        write_into(&mut packet, 5, chunk);
        out.push(packet);
        rest = tail;
        seq = seq.wrapping_add(1);
    }
    Ok(out)
}

fn write_into(dst: &mut [u8], off: usize, src: &[u8]) {
    if let Some(slot) = dst.get_mut(off..off.saturating_add(src.len())) {
        slot.copy_from_slice(src);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub msg_timeout: Duration,
    pub keepalive_interval: Duration,
    /// Upper bound for one CBOR request, after which it is cancelled and answered with
    /// CTAP2_ERR_USER_ACTION_TIMEOUT. A prompt that should end before the browser gives up needs
    /// a shorter timeout of its own (hirzd caps the approval timeout below this).
    pub processing_timeout: Duration,
    pub device_version: (u8, u8, u8),
}

impl Default for Config {
    fn default() -> Self {
        Self {
            msg_timeout: Duration::from_millis(1000),
            keepalive_interval: Duration::from_millis(100),
            processing_timeout: Duration::from_secs(120),
            device_version: (0, 1, 0),
        }
    }
}

pub type JobId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Send(Report),
    StartCbor { job: JobId, request: Vec<u8> },
    CancelJob(JobId),
    Wink,
}

#[derive(Debug)]
struct Receiving {
    cid: u32,
    command: u8,
    total: usize,
    buf: Vec<u8>,
    next_seq: u8,
    deadline: Instant,
}

#[derive(Debug)]
struct Processing {
    cid: u32,
    job: JobId,
    next_keepalive: Instant,
    deadline: Instant,
}

#[derive(Debug)]
enum State {
    Idle,
    Receiving(Receiving),
    Processing(Processing),
}

/// Where new channel identifiers come from.
#[derive(Debug, Clone, Copy)]
enum ChannelIds {
    Random,
    /// 1, 2, 3, ... for tests that need to know the identifier in advance.
    Sequential(u32),
}

/// The CTAPHID state machine. One transaction runs at a time, as on hardware tokens;
/// requests on other channels meanwhile get CTAPHID_ERR_CHANNEL_BUSY. Channel identifiers are
/// random, so a client that did not take part in the INIT exchange has to guess one.
#[derive(Debug)]
pub struct Transport {
    config: Config,
    ids: ChannelIds,
    /// Allocated channels, oldest first, at most [`MAX_CHANNELS`].
    channels: Vec<u32>,
    next_job: JobId,
    state: State,
}

fn later(now: Instant, by: Duration) -> Instant {
    now.checked_add(by).unwrap_or(now)
}

impl Transport {
    pub fn new(config: Config) -> Self {
        Self::with_ids(config, ChannelIds::Random)
    }

    #[cfg(test)]
    fn sequential(config: Config) -> Self {
        Self::with_ids(config, ChannelIds::Sequential(1))
    }

    fn with_ids(config: Config, ids: ChannelIds) -> Self {
        Self {
            config,
            ids,
            channels: Vec::new(),
            next_job: 1,
            state: State::Idle,
        }
    }

    pub fn current_job(&self) -> Option<JobId> {
        match &self.state {
            State::Processing(p) => Some(p.job),
            _ => None,
        }
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        match &self.state {
            State::Idle => None,
            State::Receiving(r) => Some(r.deadline),
            State::Processing(p) => Some(p.next_keepalive.min(p.deadline)),
        }
    }

    fn is_allocated(&self, cid: u32) -> bool {
        cid != 0 && cid != BROADCAST_CID && self.channels.contains(&cid)
    }

    fn candidate_cid(&mut self) -> u32 {
        if let ChannelIds::Random = self.ids {
            let mut bytes = [0u8; 4];
            if hirz_crypto::random_fill(&mut bytes).is_ok() {
                return u32::from_be_bytes(bytes);
            }
            // No random numbers: fall back to counting, which still never repeats an identifier in use.
            self.ids = ChannelIds::Sequential(1);
        }
        match &mut self.ids {
            ChannelIds::Sequential(next) => {
                let cid = *next;
                *next = next.wrapping_add(1);
                cid
            }
            ChannelIds::Random => 1,
        }
    }

    fn allocate_cid(&mut self) -> u32 {
        let cid = loop {
            let cid = self.candidate_cid();
            if cid != 0 && cid != BROADCAST_CID && !self.channels.contains(&cid) {
                break cid;
            }
        };
        if self.channels.len() >= MAX_CHANNELS {
            let busy = match &self.state {
                State::Idle => None,
                State::Receiving(r) => Some(r.cid),
                State::Processing(p) => Some(p.cid),
            };
            if let Some(at) = self.channels.iter().position(|c| Some(*c) != busy) {
                self.channels.remove(at);
            }
        }
        self.channels.push(cid);
        cid
    }

    fn error(cid: u32, code: u8) -> Vec<Output> {
        Self::message(cid, cmd::ERROR, &[code])
    }

    fn message(cid: u32, command: u8, payload: &[u8]) -> Vec<Output> {
        match build_message(cid, command, payload) {
            Ok(reports) => reports.into_iter().map(Output::Send).collect(),
            Err(_) => Self::message(cid, cmd::ERROR, &[err::OTHER]),
        }
    }

    fn cbor_response(cid: u32, response: &[u8]) -> Vec<Output> {
        match build_message(cid, cmd::CBOR, response) {
            Ok(reports) => reports.into_iter().map(Output::Send).collect(),
            Err(_) => Self::message(cid, cmd::CBOR, &[ctap2_status::ERR_OTHER]),
        }
    }

    fn cancel_job(cid: u32, job: JobId, status: u8) -> Vec<Output> {
        let mut out = vec![Output::CancelJob(job)];
        out.extend(Self::cbor_response(cid, &[status]));
        out
    }

    fn abort_channel(&mut self, cid: u32) -> Vec<Output> {
        match &self.state {
            State::Receiving(r) if r.cid == cid => {
                self.state = State::Idle;
                Vec::new()
            }
            State::Processing(p) if p.cid == cid => {
                let job = p.job;
                self.state = State::Idle;
                vec![Output::CancelJob(job)]
            }
            _ => Vec::new(),
        }
    }

    pub fn handle_report(&mut self, report: &[u8], now: Instant) -> Vec<Output> {
        let Ok(packet) = parse_packet(report) else {
            return Vec::new();
        };
        match packet {
            Packet::Init {
                cid,
                cmd,
                bcnt,
                data,
            } => self.handle_init_packet(cid, cmd, bcnt, data, now),
            Packet::Cont { cid, seq, data } => self.handle_cont_packet(cid, seq, data, now),
        }
    }

    fn handle_init_packet(
        &mut self,
        cid: u32,
        command: u8,
        bcnt: u16,
        data: &[u8],
        now: Instant,
    ) -> Vec<Output> {
        if command == cmd::INIT {
            return self.handle_ctaphid_init(cid, bcnt, data);
        }
        if !self.is_allocated(cid) {
            return Self::error(cid, err::INVALID_CHANNEL);
        }
        match &self.state {
            State::Processing(p) => {
                if p.cid != cid {
                    return Self::error(cid, err::CHANNEL_BUSY);
                }
                if command == cmd::CANCEL {
                    let job = p.job;
                    self.state = State::Idle;
                    return Self::cancel_job(cid, job, ctap2_status::ERR_KEEPALIVE_CANCEL);
                }
                return Self::error(cid, err::CHANNEL_BUSY);
            }
            State::Receiving(r) => {
                if r.cid != cid {
                    return Self::error(cid, err::CHANNEL_BUSY);
                }
                self.state = State::Idle;
                if command == cmd::CANCEL {
                    return Vec::new();
                }
                return Self::error(cid, err::INVALID_SEQ);
            }
            State::Idle => {}
        }
        if command == cmd::CANCEL {
            return Vec::new();
        }
        let total = usize::from(bcnt);
        if total > MAX_MESSAGE_SIZE {
            return Self::error(cid, err::INVALID_LEN);
        }
        if total <= INIT_DATA_SIZE {
            let payload = data.get(..total).unwrap_or(&[]).to_vec();
            return self.dispatch(cid, command, payload, now);
        }
        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(data);
        self.state = State::Receiving(Receiving {
            cid,
            command,
            total,
            buf,
            next_seq: 0,
            deadline: later(now, self.config.msg_timeout),
        });
        Vec::new()
    }

    fn handle_ctaphid_init(&mut self, cid: u32, bcnt: u16, data: &[u8]) -> Vec<Output> {
        if bcnt != 8 {
            return Self::error(cid, err::INVALID_LEN);
        }
        let reply_cid = if cid == BROADCAST_CID {
            None
        } else if self.is_allocated(cid) {
            Some(cid)
        } else {
            return Self::error(cid, err::INVALID_CHANNEL);
        };
        let mut out = Vec::new();
        let new_cid = match reply_cid {
            Some(own) => {
                out.extend(self.abort_channel(own));
                own
            }
            None => self.allocate_cid(),
        };
        let (major, minor, build) = self.config.device_version;
        let mut payload = Vec::with_capacity(17);
        payload.extend_from_slice(data.get(..8).unwrap_or(&[0; 8]));
        payload.extend_from_slice(&new_cid.to_be_bytes());
        payload.extend_from_slice(&[
            PROTOCOL_VERSION,
            major,
            minor,
            build,
            capability::WINK | capability::CBOR | capability::NMSG,
        ]);
        out.extend(Self::message(cid, cmd::INIT, &payload));
        out
    }

    fn handle_cont_packet(&mut self, cid: u32, seq: u8, data: &[u8], now: Instant) -> Vec<Output> {
        let State::Receiving(r) = &mut self.state else {
            return Vec::new();
        };
        if r.cid != cid {
            return Vec::new();
        }
        if seq != r.next_seq {
            self.state = State::Idle;
            return Self::error(cid, err::INVALID_SEQ);
        }
        let want = r.total.saturating_sub(r.buf.len()).min(CONT_DATA_SIZE);
        r.buf.extend_from_slice(data.get(..want).unwrap_or(&[]));
        r.next_seq = r.next_seq.wrapping_add(1);
        r.deadline = later(now, self.config.msg_timeout);
        if r.buf.len() < r.total {
            return Vec::new();
        }
        let command = r.command;
        let payload = std::mem::take(&mut r.buf);
        self.state = State::Idle;
        self.dispatch(cid, command, payload, now)
    }

    fn dispatch(&mut self, cid: u32, command: u8, payload: Vec<u8>, now: Instant) -> Vec<Output> {
        match command {
            cmd::PING => Self::message(cid, cmd::PING, &payload),
            cmd::WINK => {
                if !payload.is_empty() {
                    return Self::error(cid, err::INVALID_LEN);
                }
                let mut out = vec![Output::Wink];
                out.extend(Self::message(cid, cmd::WINK, &[]));
                out
            }
            cmd::CBOR => {
                if payload.is_empty() {
                    return Self::error(cid, err::INVALID_LEN);
                }
                let job = self.next_job;
                self.next_job = self.next_job.wrapping_add(1);
                self.state = State::Processing(Processing {
                    cid,
                    job,
                    next_keepalive: later(now, self.config.keepalive_interval),
                    deadline: later(now, self.config.processing_timeout),
                });
                vec![Output::StartCbor {
                    job,
                    request: payload,
                }]
            }
            // CTAPHID_MSG (U2F) is not implemented, as the NMSG capability says. LOCK is
            // optional and not offered.
            _ => Self::error(cid, err::INVALID_CMD),
        }
    }

    /// The job was not started (too many request threads alive): the transaction ends with
    /// CTAPHID_ERR_CHANNEL_BUSY and the transport is ready for the next request.
    pub fn job_refused(&mut self, job: JobId) -> Vec<Output> {
        match &self.state {
            State::Processing(p) if p.job == job => {
                let cid = p.cid;
                self.state = State::Idle;
                Self::error(cid, err::CHANNEL_BUSY)
            }
            _ => Vec::new(),
        }
    }

    /// Responses for jobs that were cancelled or timed out are dropped.
    pub fn job_finished(&mut self, job: JobId, response: &[u8]) -> Vec<Output> {
        match &self.state {
            State::Processing(p) if p.job == job => {
                let cid = p.cid;
                self.state = State::Idle;
                if response.is_empty() {
                    return Self::cbor_response(cid, &[ctap2_status::ERR_OTHER]);
                }
                Self::cbor_response(cid, response)
            }
            _ => Vec::new(),
        }
    }

    pub fn tick(&mut self, now: Instant, status: KeepaliveStatus) -> Vec<Output> {
        match &mut self.state {
            State::Idle => Vec::new(),
            State::Receiving(r) => {
                if now < r.deadline {
                    return Vec::new();
                }
                let cid = r.cid;
                self.state = State::Idle;
                Self::error(cid, err::MSG_TIMEOUT)
            }
            State::Processing(p) => {
                if now >= p.deadline {
                    let (cid, job) = (p.cid, p.job);
                    self.state = State::Idle;
                    return Self::cancel_job(cid, job, ctap2_status::ERR_USER_ACTION_TIMEOUT);
                }
                if now < p.next_keepalive {
                    return Vec::new();
                }
                p.next_keepalive = later(now, self.config.keepalive_interval);
                Self::message(p.cid, cmd::KEEPALIVE, &[status as u8])
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestContext {
    cancelled: Arc<AtomicBool>,
    status: Arc<AtomicU8>,
}

impl RequestContext {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            status: Arc::new(AtomicU8::new(KeepaliveStatus::Processing as u8)),
        }
    }

    /// True once the host sent CTAPHID_CANCEL, re-initialized the channel, or the request
    /// timed out. A handler waiting for the user should stop and close its prompt.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn set_status(&self, status: KeepaliveStatus) {
        self.status.store(status as u8, Ordering::SeqCst);
    }

    pub fn status(&self) -> KeepaliveStatus {
        KeepaliveStatus::from_u8(self.status.load(Ordering::SeqCst))
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Executes CTAP2 requests. `handle` runs on its own thread, so it may block while it
/// waits for the user; it should poll [`RequestContext::is_cancelled`] while doing so.
pub trait CborHandler: Send + Sync {
    /// `request` is the CTAP2 command byte followed by its CBOR parameters. Returns the
    /// status byte followed by the CBOR response. An empty response is sent as
    /// CTAP1_ERR_OTHER.
    fn handle(&self, request: &[u8], ctx: &RequestContext) -> Vec<u8>;

    fn wink(&self) {}

    /// False for requests that return at once without waiting for the user. While an earlier
    /// request that was cancelled is still running, [`run`] refuses the ones that may block with
    /// CTAPHID_ERR_CHANNEL_BUSY instead of queueing another thread behind it.
    fn may_block(&self, _request: &[u8]) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recv {
    Report(Report),
    Timeout,
    Closed,
}

pub trait ReportIo {
    fn recv(&mut self, timeout: Duration) -> io::Result<Recv>;
    fn send(&mut self, report: &Report) -> io::Result<()>;
}

/// [`ReportIo`] over a stream socket that carries exactly 64 bytes per report in each
/// direction, the framing of the hirz uhid broker. Partial reads are kept across timeouts.
#[derive(Debug)]
pub struct StreamReportIo {
    stream: UnixStream,
    buf: Report,
    filled: usize,
}

impl StreamReportIo {
    pub fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            buf: [0; REPORT_SIZE],
            filled: 0,
        }
    }
}

impl ReportIo for StreamReportIo {
    fn recv(&mut self, timeout: Duration) -> io::Result<Recv> {
        let timeout = timeout.max(Duration::from_millis(1));
        self.stream.set_read_timeout(Some(timeout))?;
        while self.filled < REPORT_SIZE {
            let Some(dst) = self.buf.get_mut(self.filled..) else {
                break;
            };
            match self.stream.read(dst) {
                Ok(0) => return Ok(Recv::Closed),
                Ok(n) => self.filled = self.filled.saturating_add(n),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(Recv::Timeout);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        self.filled = 0;
        Ok(Recv::Report(self.buf))
    }

    fn send(&mut self, report: &Report) -> io::Result<()> {
        self.stream.write_all(report)
    }
}

/// Contains no request or response contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopEvent {
    ChannelInit,
    CborRequest {
        command: u8,
        len: usize,
    },
    CborResponse {
        status: u8,
        len: usize,
    },
    Cancelled,
    /// A request was refused because an earlier, cancelled one still holds its thread.
    Busy,
}

/// Counts request threads, a cancelled request's included, until the thread ends.
#[derive(Debug, Clone, Default)]
struct Workers(Arc<AtomicUsize>);

struct WorkerGuard(Arc<AtomicUsize>);

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Workers {
    fn alive(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }

    fn enter(&self) -> WorkerGuard {
        self.0.fetch_add(1, Ordering::SeqCst);
        WorkerGuard(Arc::clone(&self.0))
    }
}

const BUSY_POLL: Duration = Duration::from_millis(10);
const IDLE_POLL: Duration = Duration::from_secs(1);

pub fn run<I: ReportIo>(
    io: &mut I,
    handler: Arc<dyn CborHandler>,
    config: Config,
    mut observe: impl FnMut(LoopEvent),
) -> io::Result<()> {
    let mut transport = Transport::new(config);
    let (tx, rx) = mpsc::channel::<(JobId, Vec<u8>)>();
    let mut running = Running::default();

    loop {
        while let Ok((job, response)) = rx.try_recv() {
            let out = transport.job_finished(job, &response);
            if !out.is_empty() {
                observe(LoopEvent::CborResponse {
                    status: response.first().copied().unwrap_or(ctap2_status::ERR_OTHER),
                    len: response.len(),
                });
            }
            execute(
                io,
                &handler,
                &tx,
                &mut transport,
                &mut running,
                out,
                &mut observe,
            )?;
        }

        let now = Instant::now();
        let timeout = match transport.next_deadline() {
            Some(deadline) => deadline.saturating_duration_since(now).min(BUSY_POLL),
            None if running.current.is_some() => BUSY_POLL,
            None => IDLE_POLL,
        };
        match io.recv(timeout)? {
            Recv::Closed => {
                if let Some((_, ctx)) = running.current.take() {
                    ctx.cancel();
                }
                return Ok(());
            }
            Recv::Timeout => {}
            Recv::Report(report) => {
                if let Ok(Packet::Init { cid, cmd: c, .. }) = parse_packet(&report)
                    && c == cmd::INIT
                    && cid == BROADCAST_CID
                {
                    observe(LoopEvent::ChannelInit);
                }
                let out = transport.handle_report(&report, Instant::now());
                execute(
                    io,
                    &handler,
                    &tx,
                    &mut transport,
                    &mut running,
                    out,
                    &mut observe,
                )?;
            }
        }

        let status = running
            .current
            .as_ref()
            .map_or(KeepaliveStatus::Processing, |(_, ctx)| ctx.status());
        let out = transport.tick(Instant::now(), status);
        execute(
            io,
            &handler,
            &tx,
            &mut transport,
            &mut running,
            out,
            &mut observe,
        )?;
        if transport.current_job().is_none() {
            running.current = None;
        }
    }
}

/// The job the transport is waiting for, and the count of request threads.
#[derive(Debug, Default)]
struct Running {
    current: Option<(JobId, RequestContext)>,
    workers: Workers,
}

fn execute<I: ReportIo>(
    io: &mut I,
    handler: &Arc<dyn CborHandler>,
    tx: &mpsc::Sender<(JobId, Vec<u8>)>,
    transport: &mut Transport,
    running: &mut Running,
    outputs: Vec<Output>,
    observe: &mut impl FnMut(LoopEvent),
) -> io::Result<()> {
    for output in outputs {
        match output {
            Output::Send(report) => io.send(&report)?,
            Output::Wink => handler.wink(),
            Output::CancelJob(job) => {
                if let Some((id, ctx)) = running.current.as_ref()
                    && *id == job
                {
                    ctx.cancel();
                    observe(LoopEvent::Cancelled);
                }
            }
            Output::StartCbor { job, request } => {
                let alive = running.workers.alive();
                if alive >= MAX_WORKERS || (alive > 0 && handler.may_block(&request)) {
                    observe(LoopEvent::Busy);
                    let refusal = transport.job_refused(job);
                    execute(io, handler, tx, transport, running, refusal, observe)?;
                    continue;
                }
                observe(LoopEvent::CborRequest {
                    command: request.first().copied().unwrap_or(0),
                    len: request.len(),
                });
                let ctx = RequestContext::new();
                let worker_ctx = ctx.clone();
                let worker_handler = Arc::clone(handler);
                let worker_tx = tx.clone();
                let guard = running.workers.enter();
                let spawned = std::thread::Builder::new()
                    .name("ctap-request".into())
                    .spawn(move || {
                        let response = worker_handler.handle(&request, &worker_ctx);
                        drop(guard);
                        let _ = worker_tx.send((job, response));
                    });
                if spawned.is_err() {
                    let _ = tx.send((job, vec![ctap2_status::ERR_OTHER]));
                }
                running.current = Some((job, ctx));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    const CID: u32 = 0x0000_0001;

    fn report(bytes: &[u8]) -> Report {
        let mut r = [0u8; REPORT_SIZE];
        r[..bytes.len()].copy_from_slice(bytes);
        r
    }

    fn sent(out: &[Output]) -> Vec<Report> {
        out.iter()
            .filter_map(|o| match o {
                Output::Send(r) => Some(*r),
                _ => None,
            })
            .collect()
    }

    fn init_request(cid: u32, nonce: [u8; 8]) -> Report {
        let mut r = report(&cid.to_be_bytes());
        r[4] = 0x86;
        r[5] = 0;
        r[6] = 8;
        r[7..15].copy_from_slice(&nonce);
        r
    }

    fn ready() -> (Transport, Instant) {
        let now = Instant::now();
        let mut t = Transport::sequential(Config::default());
        let out = t.handle_report(&init_request(BROADCAST_CID, [1; 8]), now);
        assert_eq!(sent(&out).len(), 1);
        (t, now)
    }

    fn single(cid: u32, command: u8, payload: &[u8]) -> Report {
        let mut r = report(&cid.to_be_bytes());
        r[4] = 0x80 | command;
        r[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        r[7..7 + payload.len()].copy_from_slice(payload);
        r
    }

    fn error_report(cid: u32, code: u8) -> Report {
        let mut r = report(&cid.to_be_bytes());
        r[4] = 0xbf;
        r[6] = 1;
        r[7] = code;
        r
    }

    #[test]
    fn max_message_size_is_7609() {
        assert_eq!(MAX_MESSAGE_SIZE, 7609);
    }

    #[test]
    fn parses_init_and_continuation_packets() {
        let r = report(&[0x12, 0x34, 0x56, 0x78, 0x90, 0x01, 0x02, 0xaa]);
        match parse_packet(&r).unwrap() {
            Packet::Init {
                cid,
                cmd,
                bcnt,
                data,
            } => {
                assert_eq!(cid, 0x1234_5678);
                assert_eq!(cmd, cmd::CBOR);
                assert_eq!(bcnt, 0x0102);
                assert_eq!(data.len(), 57);
                assert_eq!(data[0], 0xaa);
            }
            other => panic!("{other:?}"),
        }
        let r = report(&[0, 0, 0, 9, 0x05, 0xbb]);
        assert_eq!(
            parse_packet(&r).unwrap(),
            Packet::Cont {
                cid: 9,
                seq: 5,
                data: &r[5..]
            }
        );
        assert_eq!(parse_packet(&[0u8; 63]), Err(BadReportSize(63)));
        assert_eq!(parse_packet(&[0u8; 65]), Err(BadReportSize(65)));
    }

    #[test]
    fn builds_fragmented_messages() {
        let one = build_message(CID, cmd::PING, &[7u8; 57]).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(&one[0][..7], &[0, 0, 0, 1, 0x81, 0, 57]);

        let payload: Vec<u8> = (0..200u16).map(|i| i as u8).collect();
        let pkts = build_message(CID, cmd::CBOR, &payload).unwrap();
        // 57 + 59 + 59 = 175 < 200 <= 234
        assert_eq!(pkts.len(), 4);
        assert_eq!(&pkts[0][..7], &[0, 0, 0, 1, 0x90, 0x00, 0xc8]);
        assert_eq!(&pkts[0][7..], &payload[..57]);
        assert_eq!(&pkts[1][..5], &[0, 0, 0, 1, 0]);
        assert_eq!(&pkts[1][5..], &payload[57..116]);
        assert_eq!(pkts[3][4], 2);
        assert_eq!(&pkts[3][5..5 + 25], &payload[175..]);
        assert!(pkts[3][30..].iter().all(|&b| b == 0));

        let max = build_message(CID, cmd::CBOR, &vec![1u8; MAX_MESSAGE_SIZE]).unwrap();
        assert_eq!(max.len(), 129);
        assert_eq!(max[128][4], 0x7f);
        assert_eq!(
            build_message(CID, cmd::CBOR, &vec![1u8; MAX_MESSAGE_SIZE + 1]),
            Err(MessageTooLarge(MAX_MESSAGE_SIZE + 1))
        );
        let empty = build_message(CID, cmd::WINK, &[]).unwrap();
        assert_eq!(empty, vec![report(&[0, 0, 0, 1, 0x88, 0, 0])]);
    }

    #[test]
    fn init_on_broadcast_allocates_channel() {
        let mut t = Transport::sequential(Config::default());
        let nonce = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let out = t.handle_report(&init_request(BROADCAST_CID, nonce), Instant::now());
        let expected = report(&[
            0xff, 0xff, 0xff, 0xff, 0x86, 0x00, 0x11, // header, bcnt 17
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // nonce
            0x00, 0x00, 0x00, 0x01, // new cid
            0x02, 0x00, 0x01, 0x00, // protocol 2, version 0.1.0
            0x0d, // WINK | CBOR | NMSG
        ]);
        assert_eq!(out, vec![Output::Send(expected)]);
        let out = t.handle_report(&init_request(BROADCAST_CID, nonce), Instant::now());
        assert_eq!(sent(&out)[0][15..19], [0, 0, 0, 2]);
    }

    #[test]
    fn init_errors() {
        let mut t = Transport::sequential(Config::default());
        let mut bad = init_request(BROADCAST_CID, [0; 8]);
        bad[6] = 9;
        let out = t.handle_report(&bad, Instant::now());
        assert_eq!(
            sent(&out),
            vec![error_report(BROADCAST_CID, err::INVALID_LEN)]
        );
        let out = t.handle_report(&init_request(5, [0; 8]), Instant::now());
        assert_eq!(sent(&out), vec![error_report(5, err::INVALID_CHANNEL)]);
        let out = t.handle_report(&init_request(0, [0; 8]), Instant::now());
        assert_eq!(sent(&out), vec![error_report(0, err::INVALID_CHANNEL)]);
    }

    #[test]
    fn commands_need_an_allocated_channel() {
        let (mut t, now) = ready();
        for cid in [0, 2, BROADCAST_CID] {
            let out = t.handle_report(&single(cid, cmd::PING, b"x"), now);
            assert_eq!(sent(&out), vec![error_report(cid, err::INVALID_CHANNEL)]);
        }
    }

    #[test]
    fn ping_single_packet() {
        let (mut t, now) = ready();
        let out = t.handle_report(&single(CID, cmd::PING, b"hello"), now);
        assert_eq!(sent(&out), vec![single(CID, cmd::PING, b"hello")]);
    }

    #[test]
    fn ping_reassembles_multi_packet_messages() {
        let (mut t, now) = ready();
        let payload: Vec<u8> = (0..300u16).map(|i| (i % 251) as u8).collect();
        let pkts = build_message(CID, cmd::PING, &payload).unwrap();
        assert_eq!(pkts.len(), 6);
        for p in &pkts[..5] {
            assert!(t.handle_report(p, now).is_empty());
        }
        let out = t.handle_report(&pkts[5], now);
        assert_eq!(sent(&out), pkts);
    }

    #[test]
    fn wrong_sequence_is_rejected() {
        let (mut t, now) = ready();
        let pkts = build_message(CID, cmd::PING, &[9u8; 120]).unwrap();
        t.handle_report(&pkts[0], now);
        let out = t.handle_report(&pkts[2], now);
        assert_eq!(sent(&out), vec![error_report(CID, err::INVALID_SEQ)]);
        let out = t.handle_report(&single(CID, cmd::PING, b"a"), now);
        assert_eq!(sent(&out), vec![single(CID, cmd::PING, b"a")]);
    }

    #[test]
    fn spurious_continuations_are_ignored() {
        let (mut t, now) = ready();
        assert!(t.handle_report(&report(&[0, 0, 0, 1, 0]), now).is_empty());
        let pkts = build_message(CID, cmd::PING, &[9u8; 100]).unwrap();
        t.handle_report(&pkts[0], now);
        assert!(t.handle_report(&report(&[0, 0, 0, 7, 0]), now).is_empty());
        assert_eq!(sent(&t.handle_report(&pkts[1], now)), pkts);
    }

    #[test]
    fn reassembly_times_out() {
        let (mut t, now) = ready();
        let pkts = build_message(CID, cmd::PING, &[9u8; 100]).unwrap();
        t.handle_report(&pkts[0], now);
        assert_eq!(t.next_deadline(), Some(now + Duration::from_millis(1000)));
        assert!(
            t.tick(
                now + Duration::from_millis(999),
                KeepaliveStatus::Processing
            )
            .is_empty()
        );
        let out = t.tick(
            now + Duration::from_millis(1000),
            KeepaliveStatus::Processing,
        );
        assert_eq!(sent(&out), vec![error_report(CID, err::MSG_TIMEOUT)]);
        assert_eq!(t.next_deadline(), None);
    }

    #[test]
    fn oversized_length_is_rejected() {
        let (mut t, now) = ready();
        let mut r = single(CID, cmd::CBOR, &[]);
        r[5..7].copy_from_slice(&7610u16.to_be_bytes());
        assert_eq!(
            sent(&t.handle_report(&r, now)),
            vec![error_report(CID, err::INVALID_LEN)]
        );
    }

    #[test]
    fn other_channel_is_busy_during_reassembly() {
        let (mut t, now) = ready();
        t.handle_report(&init_request(BROADCAST_CID, [2; 8]), now);
        let pkts = build_message(CID, cmd::PING, &[9u8; 100]).unwrap();
        t.handle_report(&pkts[0], now);
        let out = t.handle_report(&single(2, cmd::PING, b"x"), now);
        assert_eq!(sent(&out), vec![error_report(2, err::CHANNEL_BUSY)]);
        let out = t.handle_report(&init_request(BROADCAST_CID, [3; 8]), now);
        assert_eq!(sent(&out)[0][15..19], [0, 0, 0, 3]);
        assert_eq!(sent(&t.handle_report(&pkts[1], now)), pkts);
    }

    #[test]
    fn wink_and_unsupported_commands() {
        let (mut t, now) = ready();
        let out = t.handle_report(&single(CID, cmd::WINK, &[]), now);
        assert_eq!(out[0], Output::Wink);
        assert_eq!(sent(&out), vec![single(CID, cmd::WINK, &[])]);
        let out = t.handle_report(&single(CID, cmd::WINK, b"x"), now);
        assert_eq!(sent(&out), vec![error_report(CID, err::INVALID_LEN)]);
        for c in [cmd::MSG, cmd::LOCK, 0x40] {
            let out = t.handle_report(&single(CID, c, b"\x01"), now);
            assert_eq!(sent(&out), vec![error_report(CID, err::INVALID_CMD)]);
        }
        let out = t.handle_report(&single(CID, cmd::CBOR, &[]), now);
        assert_eq!(sent(&out), vec![error_report(CID, err::INVALID_LEN)]);
        assert!(
            t.handle_report(&single(CID, cmd::CANCEL, &[]), now)
                .is_empty()
        );
    }

    fn start_cbor(t: &mut Transport, now: Instant) -> JobId {
        let out = t.handle_report(&single(CID, cmd::CBOR, &[0x04]), now);
        match out.as_slice() {
            [Output::StartCbor { job, request }] => {
                assert_eq!(request, &vec![0x04]);
                *job
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn cbor_keepalive_and_response() {
        let (mut t, now) = ready();
        let job = start_cbor(&mut t, now);
        assert_eq!(t.current_job(), Some(job));
        assert!(
            t.tick(now + Duration::from_millis(50), KeepaliveStatus::Processing)
                .is_empty()
        );
        let out = t.tick(
            now + Duration::from_millis(100),
            KeepaliveStatus::Processing,
        );
        assert_eq!(sent(&out), vec![report(&[0, 0, 0, 1, 0xbb, 0, 1, 1])]);
        let out = t.tick(now + Duration::from_millis(150), KeepaliveStatus::UpNeeded);
        assert!(out.is_empty());
        let out = t.tick(now + Duration::from_millis(200), KeepaliveStatus::UpNeeded);
        assert_eq!(sent(&out), vec![report(&[0, 0, 0, 1, 0xbb, 0, 1, 2])]);

        assert!(t.job_finished(job + 1, &[0x00]).is_empty());
        let out = t.job_finished(job, &[0x00, 0xa0]);
        assert_eq!(
            sent(&out),
            vec![report(&[0, 0, 0, 1, 0x90, 0, 2, 0x00, 0xa0])]
        );
        assert_eq!(t.current_job(), None);
        assert!(t.job_finished(job, &[0x00]).is_empty());
    }

    #[test]
    fn busy_while_processing() {
        let (mut t, now) = ready();
        t.handle_report(&init_request(BROADCAST_CID, [2; 8]), now);
        let job = start_cbor(&mut t, now);
        let out = t.handle_report(&single(2, cmd::PING, b"x"), now);
        assert_eq!(sent(&out), vec![error_report(2, err::CHANNEL_BUSY)]);
        let out = t.handle_report(&single(CID, cmd::PING, b"x"), now);
        assert_eq!(sent(&out), vec![error_report(CID, err::CHANNEL_BUSY)]);
        let out = t.handle_report(&single(2, cmd::CANCEL, &[]), now);
        assert_eq!(sent(&out), vec![error_report(2, err::CHANNEL_BUSY)]);
        assert_eq!(t.current_job(), Some(job));
    }

    #[test]
    fn cancel_answers_keepalive_cancel() {
        let (mut t, now) = ready();
        let job = start_cbor(&mut t, now);
        let out = t.handle_report(&single(CID, cmd::CANCEL, &[]), now);
        assert_eq!(out[0], Output::CancelJob(job));
        assert_eq!(sent(&out), vec![report(&[0, 0, 0, 1, 0x90, 0, 1, 0x2d])]);
        assert!(t.job_finished(job, &[0x00]).is_empty());
    }

    #[test]
    fn init_on_own_channel_aborts_job() {
        let (mut t, now) = ready();
        let job = start_cbor(&mut t, now);
        let out = t.handle_report(&init_request(CID, [5; 8]), now);
        assert_eq!(out[0], Output::CancelJob(job));
        let r = sent(&out);
        assert_eq!(&r[0][..7], &[0, 0, 0, 1, 0x86, 0, 17]);
        assert_eq!(&r[0][15..19], &[0, 0, 0, 1]);
        assert_eq!(t.current_job(), None);
    }

    #[test]
    fn processing_times_out() {
        let config = Config {
            processing_timeout: Duration::from_millis(250),
            ..Config::default()
        };
        let mut t = Transport::sequential(config);
        let now = Instant::now();
        t.handle_report(&init_request(BROADCAST_CID, [1; 8]), now);
        let job = start_cbor(&mut t, now);
        let out = t.tick(
            now + Duration::from_millis(250),
            KeepaliveStatus::Processing,
        );
        assert_eq!(out[0], Output::CancelJob(job));
        assert_eq!(sent(&out), vec![report(&[0, 0, 0, 1, 0x90, 0, 1, 0x2f])]);
    }

    #[test]
    fn empty_or_oversized_handler_response_is_err_other() {
        let (mut t, now) = ready();
        let job = start_cbor(&mut t, now);
        let out = t.job_finished(job, &[]);
        assert_eq!(sent(&out), vec![report(&[0, 0, 0, 1, 0x90, 0, 1, 0x7f])]);
        let job = start_cbor(&mut t, now);
        let out = t.job_finished(job, &vec![0u8; MAX_MESSAGE_SIZE + 1]);
        assert_eq!(sent(&out), vec![report(&[0, 0, 0, 1, 0x90, 0, 1, 0x7f])]);
    }

    struct WaitForCancel;

    impl CborHandler for WaitForCancel {
        fn handle(&self, request: &[u8], ctx: &RequestContext) -> Vec<u8> {
            if request.first() == Some(&0x04) {
                return vec![0x00, 0xa0];
            }
            ctx.set_status(KeepaliveStatus::UpNeeded);
            let start = Instant::now();
            while !ctx.is_cancelled() && start.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(5));
            }
            vec![ctap2_status::ERR_KEEPALIVE_CANCEL]
        }
    }

    fn read_report(s: &mut UnixStream) -> Report {
        let mut r = [0u8; REPORT_SIZE];
        s.read_exact(&mut r).unwrap();
        r
    }

    #[test]
    fn run_loop_over_socketpair() {
        let (a, mut host) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            let mut io = StreamReportIo::new(a);
            let mut events = Vec::new();
            run(&mut io, Arc::new(WaitForCancel), Config::default(), |e| {
                events.push(e)
            })
            .map(|()| events)
        });
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        let init = init_request(BROADCAST_CID, [9; 8]);
        host.write_all(&init[..10]).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        host.write_all(&init[10..]).unwrap();
        let resp = read_report(&mut host);
        assert_eq!(&resp[..7], &[0xff, 0xff, 0xff, 0xff, 0x86, 0, 17]);
        let cid = u32::from_be_bytes(resp[15..19].try_into().unwrap());

        host.write_all(&single(cid, cmd::CBOR, &[0x04])).unwrap();
        let resp = read_report(&mut host);
        assert_eq!(resp[..4], cid.to_be_bytes());
        assert_eq!(&resp[4..9], &[0x90, 0, 2, 0x00, 0xa0]);

        host.write_all(&single(cid, cmd::CBOR, &[0x01, 0xa0]))
            .unwrap();
        let mut keepalives = 0;
        while keepalives < 2 {
            let r = read_report(&mut host);
            assert_eq!(r[..4], cid.to_be_bytes());
            assert_eq!(&r[4..7], &[0xbb, 0, 1]);
            if r[7] == KeepaliveStatus::UpNeeded as u8 {
                keepalives += 1;
            }
        }
        host.write_all(&single(cid, cmd::CANCEL, &[])).unwrap();
        loop {
            let r = read_report(&mut host);
            if r[4] == 0xbb {
                continue;
            }
            assert_eq!(r[..4], cid.to_be_bytes());
            assert_eq!(&r[4..8], &[0x90, 0, 1, 0x2d]);
            break;
        }

        drop(host);
        let events = worker.join().unwrap().unwrap();
        assert_eq!(events[0], LoopEvent::ChannelInit);
        assert!(events.contains(&LoopEvent::CborRequest {
            command: 0x04,
            len: 1
        }));
        assert!(events.contains(&LoopEvent::CborResponse { status: 0, len: 2 }));
        assert!(events.contains(&LoopEvent::Cancelled));
    }

    #[test]
    fn channel_ids_are_random_and_unguessable() {
        let now = Instant::now();
        let mut t = Transport::new(Config::default());
        let mut seen = Vec::new();
        for n in 0..20u8 {
            let out = t.handle_report(&init_request(BROADCAST_CID, [n; 8]), now);
            let r = sent(&out)[0];
            let cid = u32::from_be_bytes(r[15..19].try_into().unwrap());
            assert!(cid != 0 && cid != BROADCAST_CID, "{cid:#x}");
            assert!(!seen.contains(&cid));
            seen.push(cid);
        }
        assert!(
            seen.iter().any(|c| *c > 64),
            "twenty counting identifiers would all be small: {seen:?}"
        );
        for guess in [1u32, 2, 3] {
            if !seen.contains(&guess) {
                let out = t.handle_report(&single(guess, cmd::PING, b"x"), now);
                assert_eq!(sent(&out), vec![error_report(guess, err::INVALID_CHANNEL)]);
            }
        }
        let out = t.handle_report(&single(seen[3], cmd::PING, b"x"), now);
        assert_eq!(sent(&out), vec![single(seen[3], cmd::PING, b"x")]);
    }

    #[test]
    fn a_flood_of_channels_never_drops_the_one_in_use() {
        let now = Instant::now();
        let mut t = Transport::new(Config::default());
        let out = t.handle_report(&init_request(BROADCAST_CID, [0; 8]), now);
        let mine = u32::from_be_bytes(sent(&out)[0][15..19].try_into().unwrap());
        let job = match t
            .handle_report(&single(mine, cmd::CBOR, &[0x04]), now)
            .as_slice()
        {
            [Output::StartCbor { job, .. }] => *job,
            other => panic!("{other:?}"),
        };
        for n in 0..(MAX_CHANNELS * 3) {
            t.handle_report(&init_request(BROADCAST_CID, [(n % 250) as u8; 8]), now);
        }
        assert!(t.channels.len() <= MAX_CHANNELS);
        assert!(t.is_allocated(mine));
        assert_eq!(t.current_job(), Some(job));
    }

    #[test]
    fn a_refused_job_ends_the_transaction_with_busy() {
        let (mut t, now) = ready();
        let job = start_cbor(&mut t, now);
        assert!(t.job_refused(job + 1).is_empty());
        assert_eq!(t.current_job(), Some(job));
        let out = t.job_refused(job);
        assert_eq!(sent(&out), vec![error_report(CID, err::CHANNEL_BUSY)]);
        assert_eq!(t.current_job(), None);
        assert!(t.job_refused(job).is_empty());
        let _ = start_cbor(&mut t, now);
    }

    struct Stuck {
        release: Arc<AtomicBool>,
    }

    impl CborHandler for Stuck {
        fn handle(&self, request: &[u8], _ctx: &RequestContext) -> Vec<u8> {
            if request.first() == Some(&0x04) {
                return vec![0x00, 0xa0];
            }
            while !self.release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            vec![0x00]
        }

        fn may_block(&self, request: &[u8]) -> bool {
            request.first() != Some(&0x04)
        }
    }

    fn next_non_keepalive(host: &mut UnixStream) -> Report {
        loop {
            let r = read_report(host);
            if r[4] != 0xbb {
                return r;
            }
        }
    }

    #[test]
    fn a_cancelled_request_that_is_still_running_blocks_new_ones_without_another_thread() {
        let release = Arc::new(AtomicBool::new(false));
        let (a, mut host) = UnixStream::pair().unwrap();
        let handler = Arc::new(Stuck {
            release: Arc::clone(&release),
        });
        let worker = std::thread::spawn(move || {
            let mut io = StreamReportIo::new(a);
            let mut events = Vec::new();
            run(&mut io, handler, Config::default(), |e| events.push(e)).map(|()| events)
        });
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        host.write_all(&init_request(BROADCAST_CID, [9; 8]))
            .unwrap();
        let resp = read_report(&mut host);
        let cid = u32::from_be_bytes(resp[15..19].try_into().unwrap());

        host.write_all(&single(cid, cmd::CBOR, &[0x01, 0xa0]))
            .unwrap();
        assert_eq!(read_report(&mut host)[4], 0xbb);
        host.write_all(&single(cid, cmd::CANCEL, &[])).unwrap();
        let r = next_non_keepalive(&mut host);
        assert_eq!(&r[4..8], &[0x90, 0, 1, 0x2d]);

        host.write_all(&single(cid, cmd::CBOR, &[0x01, 0xa0]))
            .unwrap();
        let r = next_non_keepalive(&mut host);
        assert_eq!(r, error_report(cid, err::CHANNEL_BUSY));

        host.write_all(&single(cid, cmd::CBOR, &[0x04])).unwrap();
        let r = next_non_keepalive(&mut host);
        assert_eq!(&r[4..9], &[0x90, 0, 2, 0x00, 0xa0]);

        release.store(true, Ordering::SeqCst);
        let mut answered = false;
        for _ in 0..100 {
            host.write_all(&single(cid, cmd::CBOR, &[0x01, 0xa0]))
                .unwrap();
            let r = next_non_keepalive(&mut host);
            if r[4] == 0x90 {
                assert_eq!(&r[5..8], &[0, 1, 0x00]);
                answered = true;
                break;
            }
            assert_eq!(r, error_report(cid, err::CHANNEL_BUSY));
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(answered, "the stuck request never released its thread");

        drop(host);
        let events = worker.join().unwrap().unwrap();
        assert!(events.contains(&LoopEvent::Busy));
    }
}
