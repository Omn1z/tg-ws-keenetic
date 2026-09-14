use serde::Serialize;
use std::{sync::Mutex, time::Instant};

#[derive(Default, Serialize)]
struct Counters {
    connections_total: u64,
    connections_active: u64,
    connections_bad: u64,
    connections_masked: u64,
    connections_ws: u64,
    connections_cfproxy: u64,
    connections_tcp_fallback: u64,
    connections_fronting: u64,
    rejected: u64,
    ws_errors: u64,
    bytes_up: u64,
    bytes_down: u64,
    pool_hits: u64,
    pool_misses: u64,
}

/// A short mutex also works on MIPS targets without 64-bit atomic instructions.
pub struct Stats {
    counters: Mutex<Counters>,
    #[cfg_attr(not(any(test, feature = "webui")), allow(dead_code))]
    started: Instant,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            counters: Mutex::new(Counters::default()),
            started: Instant::now(),
        }
    }
}

macro_rules! increment {
    ($name:ident, $field:ident) => {
        pub fn $name(&self) {
            self.counters.lock().unwrap().$field += 1;
        }
    };
}

impl Stats {
    pub fn accepted(&self) {
        let mut c = self.counters.lock().unwrap();
        c.connections_total += 1;
        c.connections_active += 1;
    }
    pub fn closed(&self) {
        let mut c = self.counters.lock().unwrap();
        c.connections_active = c.connections_active.saturating_sub(1);
    }
    increment!(bad, connections_bad);
    increment!(masked, connections_masked);
    increment!(ws, connections_ws);
    increment!(cf, connections_cfproxy);
    increment!(tcp, connections_tcp_fallback);
    increment!(fronting, connections_fronting);
    increment!(rejected, rejected);
    increment!(ws_error, ws_errors);
    increment!(pool_hit, pool_hits);
    increment!(pool_miss, pool_misses);
    pub fn add_up(&self, n: usize) {
        self.counters.lock().unwrap().bytes_up += n as u64;
    }
    pub fn add_down(&self, n: usize) {
        self.counters.lock().unwrap().bytes_down += n as u64;
    }
    #[cfg_attr(not(any(test, feature = "webui")), allow(dead_code))]
    pub fn snapshot(&self) -> serde_json::Value {
        let mut value = serde_json::to_value(&*self.counters.lock().unwrap()).unwrap();
        value["uptime_secs"] = self.started.elapsed().as_secs().into();
        value
    }
}
