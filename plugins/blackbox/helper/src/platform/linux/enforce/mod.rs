//! The Linux helper's ENFORCE side — what it changes, each change reversible: the firewall
//! ([`nft`]: one nftables table of Blackbox's own) and DNS Shield's system settings ([`dns`]).
//! Nothing here decides policy: the plan says what.

pub mod dns;
pub mod nft;
