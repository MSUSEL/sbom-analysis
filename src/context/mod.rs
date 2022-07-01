#![allow(dead_code)]

// TODO: Network badness goes up as more network vulns are detected?
// TODO: Implement score? Does it need a CVSS score? Vulnerabilies? Sbom?

use crate::cvss::BaseMetric;

#[derive(Debug, Clone)]
pub enum NetworkConfiguration {
    Public,
    Internal,
    Isolated,
}

#[derive(Debug, Clone)]
pub enum RemoteAccess {
    Public,
    VPN,
    None,
}

#[derive(Debug, Clone)]
pub enum InformationSensitivity {
    Insensitive,
    Sensitive,
}

#[derive(Debug, Clone)]
pub enum Permissions {
    Full,
    Restricted,
    Required,
    None,
}

#[derive(Debug, Clone)]
pub enum FileSystemAccess {
    Full,
    Restricted,
    Required,
    None,
}

#[derive(Debug, Clone)]
pub struct DeploymentContext {
    pub network_connection: NetworkConfiguration,
    pub remote_access: RemoteAccess,
    pub information_sensitivity: InformationSensitivity,
    pub permissions: Permissions,
    pub file_system_access: FileSystemAccess,
}

/* Score Considerations
1. Network Configuration
  Affects the attack vector, attack complexity, and the scope.
2. Remote Access
  Affects the attack vector & user interaction.
3. Information Sensitivity
    Affects the confidentiality impact.
4. Permissions
    Affects the integrity impact, availability impact, and privileges required.
 */
fn score(_ctx: &DeploymentContext, _subcomponent: &BaseMetric) -> f32 {
    todo!()
}