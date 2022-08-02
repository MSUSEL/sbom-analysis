#![allow(unused)]

use std::collections::BTreeMap;
use std::ops::{Add, AddAssign, Mul};

use chrono::{DateTime, Utc};

#[cfg(any(feature = "grype", feature = "syft", feature = "trivy"))]
pub use runner::*;

use crate::cvss::FromVector;
use crate::cvss::v3_1::*;
use crate::cvss::v3_1;
use crate::format::VulnId;

#[cfg(any(feature = "grype", feature = "syft", feature = "trivy", feature="cyclonedx"))]
/// The scoring mechanism which processes the results of the various tools
mod runner;

/// A single cvss provider
pub trait CvssProvider {
    /// Get the CVSS v3.1 score for this vulnerability
    fn cvss_v3_1(&self) -> Option<v3_1::BaseMetric>;
}

impl<T: CvssProvider> CvssProvider for &T {
    fn cvss_v3_1(&self) -> Option<v3_1::BaseMetric> {
        (*self).cvss_v3_1()
    }
}

macro_rules! comp {
    ($(#[$atr:meta])* $name:ident {
        $($(#[$attr:meta])* $field:ident),*$(,)?
    }) => {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        $(#[$atr])*
        pub enum $name {
            $($(#[$attr])* $field),*
        }
    }
}

comp!(
/// The Network Deployment category describes the public internet's access to the deployed service.
/// This category is used to evaluate the effect of a network-based vulnerability's impact on the deployed service.
NetworkConfiguration {
    /// The internet has public access to the deployed service through a web server, a database, or a network device.
    Public,
    /// The internet has public access to an adjacent service but not this service.
    Internal,
    /// The internet has no access to the deployed service.
    Isolated,
});

comp!(
/// The Remote-Access category describes the remote access to the deployed service.
/// This category is used to evaluate the effect of a remote-access vulnerability's impact on the deployed service.
RemoteAccess {
    /// The deployed service is available to specific users on the wider internet.
    Public,
    /// The deployed service is available to specific users through a VPN.
    VPN,
    /// The deployed service is available to specific users on-site.
    None,
});

comp!(
/// The Information-Sensitivity category describes the sensitivity of the deployed service's information.
/// This category is used to analyze the effect of information-targeting vulnerabilities.
InformationSensitivity {
    /// The information that the service has access to is in no way sensitive or identifying.
    Useless,
    /// The information that the service has access to is not particularly identifying or damaging but may be useful to attackers.
    Insensitive,
    /// Leaked information identifies users or groups of users. This information is more than likely useful to attackers.
    Identifying,
    /// Leaked information is likely to cause harm without being intentionally weaponized by the attacker.
    Damaging,
});

comp!(
/// Describes the level of commandline access this service has access to.
/// This category is used to analyze the effect of code-execution vulnerabilities.
Permissions {
    /// The service has superuser privileges.
    Full,
    /// The service has more privileges than the average user.
    Restricted,
    /// The service has the privileges of a default user.
    Standard,
    /// The service only has access to tools absolutely necessary for its operation.
    Required,
    /// The service has no access to any commandline tools.
    None,
});

comp!(
/// Describes how much access the service has access to the file-system.
/// This information is used in conjunction with information sensitivity to determine the effect of file-system exploits.
/// Selection of these categories should fall on the highest value based on read + write.
/// If a service cannot write to every file but can read every file, it should be given the "Full" identifier.
FileSystemAccess {
    /// The service has read or write access to all files on the host machine.
    Full,
    /// The service has access to some otherwise restricted files but more than a standard user.
    Restricted,
    /// The service has read-only access to otherwise protected file-system files.
    Standard,
    /// The service only has access to files required for its operation
    Required,
    /// The service does not require or is not given any access to the file system.
    None,
});

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The context that describes the environment in which the vulnerability was found.
pub struct DeploymentContext {
    /// The network configuration of the deployed service.
    pub network_connection: NetworkConfiguration,
    /// The remote access of the deployed service.
    pub remote_access: RemoteAccess,
    /// The information sensitivity of the deployed service.
    pub information_sensitivity: InformationSensitivity,
    /// The permissions of the deployed service.
    pub permissions: Permissions,
    /// The file-system access of the deployed service.
    pub file_system_access: FileSystemAccess,
}

impl DeploymentContext {
    /// Calculate the overall Vulnerability Score based on some cvss3.1 metric and the current context.
    ///
    /// # Arguments
    /// * `metric` - The cvss v3.1 metric representing a vulnerability.
    ///
    /// # Returns
    /// The overall Vulnerability Score.
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

    /// Calculate the network component of the vulnerability score.
    ///
    /// # Arguments
    /// * `metric` - The cvss v3.1 metric representing a vulnerability.
    ///
    /// # Returns
    /// An f32 from 0 to 1 - The network component of the vulnerability score.
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

    /// Calculate the remote access component of the vulnerability score.
    ///
    /// # Arguments
    /// * `metric` - The cvss v3.1 metric representing a vulnerability.
    ///
    /// # Returns
    /// An f32 from 0 to 1 - The remote access component of the vulnerability score.
    pub fn remote_access_v3(&self, metric: &BaseMetric) -> f32 {
        let score = match metric.privileges_required {
            PrivilegesRequired::None => 1.0,
            PrivilegesRequired::Low => 0.7,
            PrivilegesRequired::High => 0.3,
        };
        let score = score * match metric.user_interaction {
            UserInteraction::None => 1.0,
            UserInteraction::Required => 0.5,
        };
        let score = score * match self.remote_access {
            RemoteAccess::Public => 1.0,
            RemoteAccess::VPN => 0.6,
            RemoteAccess::None => 0.2,
        };
        let score = score * match self.network_connection {
            NetworkConfiguration::Public => 1.0,
            NetworkConfiguration::Internal => 0.8,
            NetworkConfiguration::Isolated => 0.1,
        };
        let score = score * match metric.attack_vector {
            AttackVector::Network => 1.0,
            AttackVector::Adjacent => 0.6,
            AttackVector::Local => 0.25,
            AttackVector::Physical => 0.1
        };
        score
    }

    /// Calculate the information sensitivity component of the vulnerability score.
    ///
    /// # Arguments
    /// * `metric` - The cvss v3.1 metric representing a vulnerability.
    ///
    /// # Returns
    /// An f32 from 0 to 1 - The information sensitivity component of the vulnerability score.
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

    /// Calculate the permissions component of the vulnerability score.
    ///
    /// # Arguments
    /// * `metric` - The cvss v3.1 metric representing a vulnerability.
    ///
    /// # Returns
    /// An f32 from 0 to 1 - The permissions component of the vulnerability score.
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

    /// Calculate the file-system access component of the vulnerability score.
    ///
    /// # Arguments
    /// * `metric` - The cvss v3.1 metric representing a vulnerability.
    ///
    /// # Returns
    /// An f32 from 0 to 1 - The file-system access component of the vulnerability score.
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

/// The broken-down score of a single piece of software.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VulnerabilityScore {
    /// The average network score of the vulnerability.
    pub network: f32,
    /// The average remote access score of the vulnerability.
    pub remote: f32,
    /// The average information sensitivity score of the vulnerability.
    pub information: f32,
    /// The average file-system access score of the vulnerability.
    pub files: f32,
    /// The average permissions score of the vulnerability.
    pub permissions: f32,
    /// The sum of the five components
    pub sum: f32,
}

/// General information about a what scayl version generated a particular score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaylInfo {
    /// The version of Scayl that generated the score.
    version: String,
    /// The date & time that the score was generated at.
    generated_at: DateTime<Utc>,
}

impl ScaylInfo {
    /// Create a new ScaylInfo based on the current time & version.
    pub fn current() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            generated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The score report of a single piece of software.
pub struct DeploymentScore {
    /// The context used to generate the score.
    pub context: DeploymentContext,
    /// The name of the software being scored.
    pub source: String,
    /// The current version & date of the generated score.
    pub scayl: ScaylInfo,
    /// The score of the software.
    pub cumulative: VulnerabilityScore,
    /// The score of the software broken down by component.
    pub scores: BTreeMap<VulnId, VulnerabilityScore>,
}

impl DeploymentScore {
    /// Create a new DeploymentScore based on the current time & version.
    ///
    /// # Returns
    /// The average network score of the vulnerability.
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
        self + &rhs
    }
}

impl<'a> Add<&'a VulnerabilityScore> for VulnerabilityScore {
    type Output = VulnerabilityScore;

    fn add(self, rhs: &'a VulnerabilityScore) -> Self::Output {
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
        AddAssign::add_assign(self, &rhs)
    }
}

impl<'a> AddAssign<&'a VulnerabilityScore> for VulnerabilityScore {
    fn add_assign(&mut self, rhs: &'a VulnerabilityScore) {
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