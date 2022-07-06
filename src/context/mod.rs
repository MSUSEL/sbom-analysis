#![allow(dead_code)]

// TODO: Network badness goes up as more network vulns are detected?

mod runner;
mod vuln;

pub use runner::*;

use crate::cvss::v3_1::*;

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
    Useless,
    Insensitive,
    Identifying,
    Damaging,
}

#[derive(Debug, Clone)]
pub enum Permissions {
    Full,
    Restricted,
    Standard,
    Required,
    None,
}

#[derive(Debug, Clone)]
pub enum FileSystemAccess {
    Full,
    Restricted,
    Standard,
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
fn score_cvss(ctx: &DeploymentContext, subcomponent: &BaseMetric) -> f32 {
    let network_potential = match subcomponent.attack_vector {
        AttackVector::Network => 1.0,
        AttackVector::Adjacent => 2.0 / 3.0,
        AttackVector::Local => 1.0 / 3.0,
        AttackVector::Physical => 0.00,
    };
    let network_potential = network_potential * match ctx.network_connection {
        NetworkConfiguration::Public => 1.0,
        NetworkConfiguration::Internal => 0.5,
        NetworkConfiguration::Isolated => 0.0,
    };
    let remote_access_potential = match subcomponent.user_interaction {
        UserInteraction::None => 1.0,
        UserInteraction::Required => 0.8,
    };
    let remote_access_potential = remote_access_potential * match ctx.remote_access {
        RemoteAccess::Public => 1.0,
        RemoteAccess::VPN => 0.5,
        RemoteAccess::None => 0.0,
    };
    let information_breach_potential = match subcomponent.scope {
        Scope::Unchanged => 0.8,
        Scope::Changed => 1.0,
    };
    let information_breach_potential = information_breach_potential * match ctx.information_sensitivity {
        InformationSensitivity::Useless => 0f32,
        InformationSensitivity::Insensitive => 1f32/3.0,
        InformationSensitivity::Identifying => 2f32/3.0,
        InformationSensitivity::Damaging => 1f32,
    };
    let permissions_potential = match subcomponent.privileges_required {
        PrivilegesRequired::None => 1.0,
        PrivilegesRequired::Low => 0.8,
        PrivilegesRequired::High => 0.2,
    };
    let permissions_potential = (permissions_potential - match ctx.permissions {
        Permissions::Full => 0f32,
        Permissions::Restricted => 0.25,
        Permissions::Standard => 0.5,
        Permissions::Required => 0.75,
        Permissions::None => 1.0,
    }).max(0f32);
    let file_system_effect = match subcomponent.scope {
        Scope::Unchanged => 0.8,
        Scope::Changed => 1.0,
    };
    let file_system_access_potential = file_system_effect * match ctx.file_system_access {
        FileSystemAccess::Full => 1.0,
        FileSystemAccess::Restricted => 0.75,
        FileSystemAccess::Standard => 0.5,
        FileSystemAccess::Required => 0.25,
        FileSystemAccess::None => 0.0,
    };
    const WEIGHTS: [f32; 5] = [1.2, 1.1, 0.9, 1.0, 0.8];
    assert!((WEIGHTS.iter().sum::<f32>() - 5.0).abs() < 0.0001);
    let vals: [f32; 5] = [
        network_potential,
        remote_access_potential,
        information_breach_potential,
        permissions_potential,
        file_system_access_potential
    ];
    WEIGHTS.iter().zip(vals.iter()).map(|(w, v)| v * w).sum::<f32>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_score() {
        let ctx = DeploymentContext {
            network_connection: NetworkConfiguration::Isolated,
            remote_access: RemoteAccess::Public,
            information_sensitivity: InformationSensitivity::Identifying,
            permissions: Permissions::Full,
            file_system_access: FileSystemAccess::Full,
        };
        let base = BaseMetric {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Changed,
            confidentiality_impact: ImpactMetric::High,
            integrity_impact: ImpactMetric::High,
            availability_impact: ImpactMetric::High,
        };
        println!("Sum: {:.2}", score_cvss(&ctx, &base));
    }
}