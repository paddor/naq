//! Load generators and benchmarks for naq.
//!
//! [`load`] drives a NATS server over raw wire: batched publishers, counting
//! subscribers, a window that keeps every message deliverable. [`sink`] is
//! a fake server that measures the load generator alone. [`codec`] measures
//! the `naq-proto` codec on one core. [`hop`] measures a batched OMQ hop
//! between lanes, as between peers. [`index`] measures subject lookups.
//! [`suite`] runs the load against `nats-server` and naq and gates naq on
//! the ratio.

#![forbid(unsafe_code)]

pub mod cli;
pub mod codec;
pub mod conn;
pub mod cpu;
pub mod hop;
pub mod index;
pub mod load;
pub mod sink;
pub mod suite;
pub mod wire;
