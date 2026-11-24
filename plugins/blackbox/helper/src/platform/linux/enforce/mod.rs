//! The Linux helper's ENFORCE side — what it changes, each change reversible: the firewall
//! ([`nft`]: one nftables table of Blackbox's own); DNS Shield's system settings land next.
//! Nothing here decides policy: the plan says what.

pub mod nft;
