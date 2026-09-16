//! aci-worker's own library surface: session_protocol, the AEAD/ECDH wire
//! framing session_master.rs's client leg speaks. Split out of
//! attested-python-execution (private repo) into this public one alongside
//! session_master.rs itself, since neither has any business-sensitive
//! content of its own -- see that repo's own history for why (the OSS/
//! private boundary is "does this need to stay private," not "is this
//! ACI-specific").
//!
//! attested-python-execution's own attested_session.rs/callback.rs (the
//! broker side of this same protocol, which DOES stay private) depend on
//! this crate externally now, rather than owning a local copy -- one
//! implementation of the wire format, not two kept in sync by hand.

pub mod session_protocol;
