//! Private registries: the policy grammar that declares them, the credentials
//! they authenticate with, and the one URL prefix test every check shares
//! (docs/agent/DESIGNS.md §4 "Private registries").

pub mod config;
pub mod covers;
pub mod effective;
