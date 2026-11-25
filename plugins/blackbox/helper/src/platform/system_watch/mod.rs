//! The system watch's OS-neutral state: what the last look saw and the events a change queues —
//! [`exposure`] (listeners the network can reach), [`items`] (what starts or runs by itself, and
//! its mark), [`sudoers`] (sudo without a password) and [`tamper`] (the settings that get around protection). Each OS's observe side
//! (`platform/<os>/observe/`) reads the system and fills these; nothing here reads or changes
//! the system beyond marking a file safely (`crate::safe_read`).

pub mod exposure;
pub mod items;
pub mod plan;
pub mod sudoers;
pub mod tamper;
