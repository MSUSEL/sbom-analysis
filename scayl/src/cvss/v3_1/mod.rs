//! The CVSS v3.1 scoring specification
//!
//! <https://www.first.org/cvss/v3.1/specification-document>

pub use base::*;
pub use environmental::*;
pub use temporal::*;

/// The base component of the CVSS v3.1 scoring specification.
mod base;

/// The temporal component of the CVSS v3.1 scoring specification.
mod temporal;

/// The environmental component of the CVSS v3.1 scoring specification.
mod environmental;

/// The roundup function specified in the CVSS v3.1 specification.
pub fn roundup(v: f32) -> f32 {
    let int_input = (v * 1e5).round();
    if int_input % 1e4 == 0.0 {
        int_input / 1e5
    } else {
        (1.0 + (int_input / 1e4).floor()) / 10.0
    }
}

impl BaseMetric {
    /// Calculates the CVSS v3.1 Base Metric Score.
    pub fn base_score(&self) -> f32 {
        let impact = self.impact();
        if impact <= 0.0 {
            0.0
        } else {
            roundup(if let Scope::Unchanged = self.scope {
                impact + self.exploitability()
            } else {
                1.08 * (impact + self.exploitability())
            }.min(10.0))
        }
    }

    /// Calculates the CVSS v3.1 impact score.
    fn impact(&self) -> f32 {
        let iss = self.impact_sub_score();
        match self.scope {
            Scope::Unchanged => 6.42 * iss,
            Scope::Changed => 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15),
        }
    }

    /// Calculates the CVSS v3.1 impact sub-score.
    fn impact_sub_score(&self) -> f32 {
        let a = 1.0 - Self::impact_value(&self.confidentiality_impact);
        let b = 1.0 - Self::impact_value(&self.integrity_impact);
        let c = 1.0 - Self::impact_value(&self.availability_impact);
        1.0 - a * b * c
    }

    /// Calculates the CVSS v3.1 exploitability score.
    fn exploitability(&self) -> f32 {
        8.22
            * self.attack_vector()
            * self.attack_complexity()
            * self.privileges_required()
            * self.user_interaction()
    }

    /// Calculates the CVSS v3.1 attack vector score.
    fn attack_vector(&self) -> f32 {
        match self.attack_vector {
            AttackVector::Network => 0.85,
            AttackVector::Adjacent => 0.62,
            AttackVector::Local => 0.55,
            AttackVector::Physical => 0.2,
        }
    }

    /// Calculates the CVSS v3.1 attack complexity score.
    fn attack_complexity(&self) -> f32 {
        match self.attack_complexity {
            AttackComplexity::Low => 0.77,
            AttackComplexity::High => 0.44,
        }
    }

    /// Calculates the CVSS v3.1 privileges required score.
    fn privileges_required(&self) -> f32 {
        match self.privileges_required {
            PrivilegesRequired::None => 0.85,
            PrivilegesRequired::Low => match self.scope {
                Scope::Unchanged => 0.62,
                Scope::Changed => 0.68,
            },
            PrivilegesRequired::High => match self.scope {
                Scope::Unchanged => 0.27,
                Scope::Changed => 0.5,
            },
        }
    }

    /// Calculates the CVSS v3.1 user interaction score.
    fn user_interaction(&self) -> f32 {
        match self.user_interaction {
            UserInteraction::None => 0.85,
            UserInteraction::Required => 0.62,
        }
    }

    /// Calculates the CVSS v3.1 impact value.
    fn impact_value(value: &ImpactMetric) -> f32 {
        match value {
            ImpactMetric::None => 0.0,
            ImpactMetric::Low => 0.22,
            ImpactMetric::High => 0.56,
        }
    }
}