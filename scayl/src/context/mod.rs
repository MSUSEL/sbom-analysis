#![allow(unused)]

use std::collections::BTreeMap;
use std::ops::{Add, AddAssign, Mul};


use crate::cvss::v3_1::*;
use crate::format::VulnId;

#[cfg(any(feature = "grype", feature = "syft", feature = "trivy"))]
mod runner;
mod vuln;

#[cfg(any(feature = "grype", feature = "syft", feature = "trivy"))]
pub use runner::*;
pub use vuln::*;

macro_rules! comp {
    ($name:ident {
        $($field:ident),*$(,)?
    }) => {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub enum $name {
            $($field),*
        }
    }
}

comp!(NetworkConfiguration {
    Public,
    Internal,
    Isolated,
});

comp!(RemoteAccess {
    Public,
    VPN,
    None,
});

comp!(InformationSensitivity {
    Useless,
    Insensitive,
    Identifying,
    Damaging,
});

comp!(Permissions {
    Full,
    Restricted,
    Standard,
    Required,
    None,
});

comp!(FileSystemAccess {
    Full,
    Restricted,
    Standard,
    Required,
    None,
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentContext {
    pub network_connection: NetworkConfiguration,
    pub remote_access: RemoteAccess,
    pub information_sensitivity: InformationSensitivity,
    pub permissions: Permissions,
    pub file_system_access: FileSystemAccess,
}

impl DeploymentContext {
    /// Calculate the overall Vulnerability Score based on some cvss3.1 metric and the current context.
    pub fn score_v3(&self, metric: &BaseMetric) -> VulnerabilityScore {
        let nw = self.network_v3(metric);
        let rem = self.remote_access_v3(metric);
        let inf = self.information_sensitivity_v3(metric);
        let perm = self.permissions_v3(metric);
        let fs = self.file_system_access_v3(metric);

        VulnerabilityScore {
            sum: nw + rem + inf + perm + fs,
            network: nw,
            files: fs,
            remote: rem,
            information: inf,
            permissions: perm,
        }
    }

    pub fn network_v3(&self, metric: &BaseMetric) -> f32 {
        let score = match metric.attack_vector {
            AttackVector::Network => 1f32,
            AttackVector::Adjacent => 0.8,
            AttackVector::Local => 0.4,
            AttackVector::Physical => 0.01,
        };
        let score = score * match metric.privileges_required {
            PrivilegesRequired::None => 1.0,
            PrivilegesRequired::Low => 0.4,
            PrivilegesRequired::High => 0.2,
        };
        let score = score * match metric.availability_impact {
            ImpactMetric::None => 0.5,
            ImpactMetric::Low => 0.75,
            ImpactMetric::High => 1.0,
        };
        let score = score * match self.network_connection {
            NetworkConfiguration::Public => 1.0,
            NetworkConfiguration::Internal => 0.8,
            NetworkConfiguration::Isolated => 0.1,
        };
        score
    }

    pub fn remote_access_v3(&self, metric: &BaseMetric) -> f32 {
        let score = match metric.privileges_required {
            PrivilegesRequired::None => 1.0,
            PrivilegesRequired::Low => 0.9,
            PrivilegesRequired::High => 0.8,
        };
        let score = score * match metric.user_interaction {
            UserInteraction::None => 1.0,
            UserInteraction::Required => 0.9,
        };
        let score = score * match self.remote_access {
            RemoteAccess::Public => 1.0,
            RemoteAccess::VPN => 0.8,
            RemoteAccess::None => 0.4,
        };
        score
    }

    pub fn information_sensitivity_v3(&self, metric: &BaseMetric) -> f32 {
        let score = match metric.confidentiality_impact {
            ImpactMetric::High => 1.0,
            ImpactMetric::Low => 0.7,
            ImpactMetric::None => 0.4,
        };
        let score = score * match self.information_sensitivity {
            InformationSensitivity::Useless => 0.25,
            InformationSensitivity::Insensitive => 0.5,
            InformationSensitivity::Identifying => 0.75,
            InformationSensitivity::Damaging => 1.0,
        };
        score
    }

    pub fn permissions_v3(&self, metric: &BaseMetric) -> f32 {
        let score = match metric.integrity_impact {
            ImpactMetric::None => 0.4,
            ImpactMetric::Low => 0.7,
            ImpactMetric::High => 1.0,
        };
        let score = score * match metric.availability_impact {
            ImpactMetric::None => 0.4,
            ImpactMetric::Low => 0.7,
            ImpactMetric::High => 1.0,
        };
        let score = score * match self.permissions {
            Permissions::Full => 1.0,
            Permissions::Restricted => 0.8,
            Permissions::Standard => 0.6,
            Permissions::Required => 0.2,
            Permissions::None => 0.01,
        };
        score
    }

    pub fn file_system_access_v3(&self, metric: &BaseMetric) -> f32 {
        let score = match metric.integrity_impact {
            ImpactMetric::None => 0.4,
            ImpactMetric::Low => 0.7,
            ImpactMetric::High => 1.0,
        };
        let score = score * match self.file_system_access {
            FileSystemAccess::Full => 1.0,
            FileSystemAccess::Restricted => 0.8,
            FileSystemAccess::Standard => 0.4,
            FileSystemAccess::Required => 0.2,
            FileSystemAccess::None => 0.01,
        };
        score
    }
}

#[derive(Debug, Clone, Default)]
pub struct VulnerabilityScore {
    pub sum: f32,
    pub network: f32,
    pub files: f32,
    pub remote: f32,
    pub information: f32,
    pub permissions: f32,
}

#[derive(Debug, Clone)]
pub struct DeploymentScore {
    pub scores: BTreeMap<VulnId, VulnerabilityScore>,
}

impl DeploymentScore {
    pub fn sum(&self) -> (f32, f32) {
        let mut sum = 0.0;

        for (_, score) in &self.scores {
            sum += score.sum;
        }

        (sum, self.scores.len() as f32 * 5.0)
    }
}

impl Add<VulnerabilityScore> for VulnerabilityScore {
    type Output = VulnerabilityScore;

    fn add(self, rhs: VulnerabilityScore) -> Self::Output {
        VulnerabilityScore {
            sum: self.sum + rhs.sum,
            network: self.network + rhs.network,
            files: self.files + rhs.files,
            remote: self.remote + rhs.remote,
            information: self.information + rhs.information,
            permissions: self.permissions + rhs.permissions,
        }
    }
}

impl AddAssign<VulnerabilityScore> for VulnerabilityScore {
    fn add_assign(&mut self, rhs: VulnerabilityScore) {
        self.sum += rhs.sum;
        self.network += rhs.network;
        self.files += rhs.files;
        self.remote += rhs.remote;
        self.information += rhs.information;
        self.permissions += rhs.permissions;
    }
}

impl<T: Into<f32>> Mul<T> for VulnerabilityScore {
    type Output = VulnerabilityScore;

    fn mul(self, rhs: T) -> Self::Output {
        let rhs = rhs.into();
        VulnerabilityScore {
            sum: self.sum * rhs,
            network: self.network * rhs,
            files: self.files * rhs,
            remote: self.remote * rhs,
            information: self.information * rhs,
            permissions: self.permissions * rhs,
        }
    }
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
        println!("Sum: {:?}", ctx.score_v3(&base));
    }
}