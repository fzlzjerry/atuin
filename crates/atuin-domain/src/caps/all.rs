use serde::{Deserialize, Serialize};

use super::Capability;

/// The capability-negotiation protocol itself, expressed as a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitiesCap {
    /// The version of the capability-negotiation protocol the server implements.
    pub version: u32,
}

impl Capability for CapabilitiesCap {
    fn static_name() -> &'static str {
        "sh.atuin.server/capabilities"
    }

    fn name(&self) -> &'static str {
        Self::static_name()
    }

    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

/// The client history "packfile" feature.
///
/// This capability communicates that the server supports the creation of packfiles. For more
/// details, read the docs of `atuin_client::packfile`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackfileCap {
    /// The version of the packfile protocol the server implements.
    pub version: u32,

    /// How many history records the client should bundle into each packfile manifest.
    ///
    /// This is a server-authoritative directive: the client reads it from the server's
    /// advertisement to size its packing, replacing any client-side default. The count a node
    /// carries in its *own* advertisement is not meaningful -- only the server's value governs
    /// packing.
    pub record_count: u64,
}

impl Capability for PackfileCap {
    fn static_name() -> &'static str {
        "sh.atuin.server/records.packfile"
    }

    fn name(&self) -> &'static str {
        Self::static_name()
    }

    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}
