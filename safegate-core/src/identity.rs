//! Agent identity context shared by SafeGate components.

/// Identity and authorization attributes associated with an inbound agent request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentContext {
    /// Stable identifier for the calling agent.
    pub agent_id: String,
    /// Tenant to which the calling agent belongs.
    pub tenant_id: String,
    /// Roles granted to the agent.
    pub roles: Vec<String>,
    /// Whether the request supplied a validated credential.
    pub authenticated: bool,
}
