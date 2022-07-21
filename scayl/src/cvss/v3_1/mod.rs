pub use base::*;
pub use environmental::*;
pub use temporal::*;

mod base;
mod temporal;
mod environmental;

pub fn roundup(v: f32) -> f32 {
    let int_input = (v * 1e5).round();
    if int_input % 1e4 == 0.0 {
        int_input / 1e5
    } else {
        (1.0 + (int_input / 1e4).floor()) / 10.0
    }
}

impl BaseMetric {
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

    fn impact(&self) -> f32 {
        let iss = self.impact_sub_score();
        match self.scope {
            Scope::Unchanged => 6.42 * iss,
            Scope::Changed => 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15),
        }
    }

    fn impact_sub_score(&self) -> f32 {
        let a = 1.0 - Self::impact_value(&self.confidentiality_impact);
        let b = 1.0 - Self::impact_value(&self.integrity_impact);
        let c = 1.0 - Self::impact_value(&self.availability_impact);
        1.0 - a * b * c
    }

    fn exploitability(&self) -> f32 {
        8.22
            * self.attack_vector()
            * self.attack_complexity()
            * self.privileges_required()
            * self.user_interaction()
    }

    fn attack_vector(&self) -> f32 {
        match self.attack_vector {
            AttackVector::Network => 0.85,
            AttackVector::Adjacent => 0.62,
            AttackVector::Local => 0.55,
            AttackVector::Physical => 0.2,
        }
    }

    fn attack_complexity(&self) -> f32 {
        match self.attack_complexity {
            AttackComplexity::Low => 0.77,
            AttackComplexity::High => 0.44,
        }
    }

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

    fn user_interaction(&self) -> f32 {
        match self.user_interaction {
            UserInteraction::None => 0.85,
            UserInteraction::Required => 0.62,
        }
    }

    fn impact_value(value: &ImpactMetric) -> f32 {
        match value {
            ImpactMetric::None => 0.0,
            ImpactMetric::Low => 0.22,
            ImpactMetric::High => 0.56,
        }
    }
}