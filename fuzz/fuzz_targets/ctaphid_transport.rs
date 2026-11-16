#![no_main]

//! Drives the CTAPHID state machine with a script of `(control byte, 64-byte report)`
//! records. Control bits: 0..=4 advance the clock by n * 64 ms, 5 runs `tick` first,
//! 6 finishes the running job with a response cut from the report, 7 advances 121 s.

use std::time::{Duration, Instant};

use hirz_ctap::hid::{
    self, Config, JobId, KeepaliveStatus, MAX_MESSAGE_SIZE, Output, Packet, REPORT_SIZE, Transport,
};
use libfuzzer_sys::fuzz_target;

#[derive(Default)]
struct Model {
    running: Option<JobId>,
    last_job: JobId,
}

impl Model {
    fn apply(&mut self, outputs: &[Output]) {
        for o in outputs {
            match o {
                Output::Send(report) => {
                    if let Packet::Init { bcnt, .. } = hid::parse_packet(report).expect("report") {
                        assert!(usize::from(bcnt) <= MAX_MESSAGE_SIZE);
                    }
                }
                Output::StartCbor { job, request } => {
                    assert!(self.running.is_none(), "one transaction at a time");
                    assert!(*job > self.last_job, "job ids increase");
                    assert!(!request.is_empty() && request.len() <= MAX_MESSAGE_SIZE);
                    self.last_job = *job;
                    self.running = Some(*job);
                }
                Output::CancelJob(job) => {
                    assert_eq!(self.running, Some(*job), "only the running job is cancelled");
                    self.running = None;
                }
                Output::Wink => {}
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut t = Transport::new(Config::default());
    let mut now = Instant::now();
    let mut model = Model::default();
    for record in data.chunks(REPORT_SIZE + 1) {
        let Some((&ctl, report)) = record.split_first() else {
            break;
        };
        now += Duration::from_millis(u64::from(ctl & 0x1f) * 64);
        if ctl & 0x80 != 0 {
            now += Duration::from_secs(121);
        }
        if ctl & 0x20 != 0 {
            let out = t.tick(now, KeepaliveStatus::Processing);
            model.apply(&out);
            assert_eq!(t.current_job(), model.running);
        }
        if ctl & 0x40 != 0 {
            match model.running {
                Some(job) => {
                    let len = usize::from(report.first().copied().unwrap_or(0)) % 65;
                    let response = report.get(..len).unwrap_or(report);
                    let out = t.job_finished(job, response);
                    assert!(out.iter().all(|o| matches!(o, Output::Send(_))));
                    assert!(!out.is_empty(), "a finished job is always answered");
                    model.running = None;
                    model.apply(&out);
                }
                None if model.last_job > 0 => {
                    assert!(t.job_finished(model.last_job, &[0]).is_empty());
                }
                None => {}
            }
            assert_eq!(t.current_job(), model.running);
        }
        let out = t.handle_report(report, now);
        if report.len() != REPORT_SIZE {
            assert!(out.is_empty());
        }
        model.apply(&out);
        assert_eq!(t.current_job(), model.running);
    }
});
