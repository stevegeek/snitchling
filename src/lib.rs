//! snitchling: a small, fast UI for the OpenSnitch daemon.

pub mod pb {
    tonic::include_proto!("protocol");
}

pub mod hub;
pub mod rules;
pub mod service;
