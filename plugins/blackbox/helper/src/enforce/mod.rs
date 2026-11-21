//! The helper's ENFORCE side — what it changes on this Mac, every part reversible.
//!
//! [`dns`]: the local resolver that refuses listed names; [`system`]: pointing the Mac's DNS at
//! it and restoring the saved servers exactly; [`pf`]: the packet-filter anchor (Threat
//! Firewall, cutting malicious connections, SSH lockdown, Lock remote access, blocked
//! addresses), removed when nothing is on; [`sessions`]: ending the one remote session the user
//! chose, after checking it is still that session; [`posture`]: the safe posture fixes the person
//! asked for, each remembered so it can be put back; [`restore`]: the opt-in DNS tamper guard. Undo: the
//! helper restores DNS and releases pf whenever a protection is switched off or the helper stops.

pub mod dns;
pub mod pf;
pub mod posture;
pub mod restore;
pub mod sessions;
pub mod system;
