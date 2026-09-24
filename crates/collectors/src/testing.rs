//! Shared test utilities (compiled only for tests).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sentinel_core::{DnsRecord, DnsRecordData, DnsRecordType};

use crate::clock::testing::FixedClock;
use crate::collector::{CollectContext, RequestBudget};
use crate::dns::{DnsLookupFuture, DnsQueryError, DnsResolver};
use crate::http::HttpClient;

/// What the fake resolver answers for one (name, type).
#[derive(Clone)]
pub(crate) enum Answer {
    Records(Vec<DnsRecordData>),
    Error(DnsQueryError),
    /// Never answers (to exercise timeouts).
    Hang,
}

/// In-memory resolver. Unknown (name, type) pairs answer `NoRecords`.
#[derive(Default)]
pub(crate) struct FakeResolver {
    pub(crate) answers: HashMap<(String, DnsRecordType), Answer>,
    pub(crate) queried: Mutex<Vec<(String, DnsRecordType)>>,
}

impl FakeResolver {
    pub(crate) fn with(mut self, name: &str, record_type: DnsRecordType, answer: Answer) -> Self {
        self.answers.insert((name.to_owned(), record_type), answer);
        self
    }

    pub(crate) fn records(
        self,
        name: &str,
        record_type: DnsRecordType,
        data: Vec<DnsRecordData>,
    ) -> Self {
        self.with(name, record_type, Answer::Records(data))
    }

    pub(crate) fn txt(self, name: &str, texts: &[&str]) -> Self {
        let data = texts
            .iter()
            .map(|t| DnsRecordData::Txt {
                text: (*t).to_owned(),
            })
            .collect();
        self.records(name, DnsRecordType::Txt, data)
    }
}

impl DnsResolver for FakeResolver {
    fn description(&self) -> &'static str {
        "fake"
    }

    fn lookup<'a>(&'a self, name: &'a str, record_type: DnsRecordType) -> DnsLookupFuture<'a> {
        Box::pin(async move {
            self.queried
                .lock()
                .unwrap()
                .push((name.to_owned(), record_type));
            match self.answers.get(&(name.to_owned(), record_type)).cloned() {
                Some(Answer::Records(data)) => Ok(data
                    .into_iter()
                    .map(|d| DnsRecord::new(name, 300, d))
                    .collect()),
                Some(Answer::Error(error)) => Err(error),
                Some(Answer::Hang) => std::future::pending().await,
                None => Err(DnsQueryError::NoRecords),
            }
        })
    }
}

impl FakeResolver {
    /// Names queried so far, in order.
    pub(crate) fn queried_names(&self) -> Vec<String> {
        self.queried
            .lock()
            .unwrap()
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }
}

/// A collection context for calling a collector directly (without the engine).
pub(crate) fn context(http: HttpClient, max_requests: u32) -> CollectContext {
    CollectContext::new(
        http,
        Arc::new(RequestBudget::new(max_requests)),
        Arc::new(FixedClock::default()),
    )
}

/// In-memory log sink.
#[derive(Clone, Default)]
pub(crate) struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl LogCapture {
    pub(crate) fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// A process-wide TRACE-level capture of every log line written by any test
/// in this binary (threads without a scoped subscriber). A global default
/// avoids the thread-local dispatcher races that make scoped capture flaky
/// under parallel tests.
pub(crate) fn global_log_capture() -> &'static LogCapture {
    static CAPTURE: std::sync::OnceLock<LogCapture> = std::sync::OnceLock::new();
    CAPTURE.get_or_init(|| {
        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(capture.clone())
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        capture
    })
}
