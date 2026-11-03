//! Load generators and benchmarks for naq.
//!
//! [`load`] drives a NATS server over raw wire: batched publishers, counting
//! subscribers, a window that keeps every message deliverable. [`sink`] is
//! a fake server that measures the load generator alone.

#![forbid(unsafe_code)]

pub mod cli;
pub mod conn;
pub mod cpu;
pub mod load;
pub mod sink;
pub mod wire;
