use crate::cvss::roundup;

#[derive(Debug, Clone)]
pub struct BaseMetric {
    pub attack_vector: AttackVector,
    pub attack_complexity: AttackComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
    pub scope: Scope,
    pub confidentiality_impact: ImpactValue,
    pub integrity_impact: ImpactValue,
    pub availability_impact: ImpactValue,
}

#[derive(Debug, Clone)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

#[derive(Debug, Clone)]
pub enum AttackComplexity {
    Low,
    High,
}

#[derive(Debug, Clone)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

#[derive(Debug, Clone)]
pub enum UserInteraction {
    None,
    Required,
}

#[derive(Debug, Clone)]
pub enum Scope {
    Unchanged,
    Changed,
}

#[derive(Debug, Clone)]
pub enum ImpactValue {
    None,
    Low,
    High,
}

impl BaseMetric {
    pub fn score(&self) -> f32 {
        roundup(self.raw_score()).min(10f32)
    }

    pub fn scores(&self) -> (f32, f32, f32) {
        let impact = self.impact();
        if impact <= 0.0 {
            (0.0, 0.0, 0.0)
        } else {
            let exploitability = self.exploitability();
            let base = impact + exploitability;
            let score = match self.scope {
                Scope::Unchanged => base,
                Scope::Changed => 1.08 * base,
            }.min(10.0);
            let score = roundup(score);
            (score, roundup(impact), roundup(exploitability))
        }
    }

    pub fn raw_score(&self) -> f32 {
        let impact = self.impact();
        if impact <= 0f32 {
            0f32
        } else {
            let sum = impact + self.exploitability();
            match self.scope {
                Scope::Unchanged => sum,
                Scope::Changed => 1.08 * sum,
            }
        }
    }

    pub fn impact(&self) -> f32 {
        let iss = self.impact_sub_score();
        match self.scope {
            Scope::Unchanged => 6.42 * iss,
            Scope::Changed => 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15),
        }
    }

    pub fn impact_sub_score(&self) -> f32 {
        1.0 - (
            (1.0 - self.confidentiality_impact.value())
                * (1.0 - self.integrity_impact.value())
                * (1.0 - self.availability_impact.value())
        )
    }

    pub fn exploitability(&self) -> f32 {
        8.22 * self.attack_vector.value()
            * self.attack_complexity.value()
            * self.privileges_required.value(&self.scope)
            * self.user_interaction.value()
    }
}

impl ImpactValue {
    pub fn value(&self) -> f32 {
        match self {
            ImpactValue::None => 0.0,
            ImpactValue::Low => 0.22,
            ImpactValue::High => 0.56,
        }
    }
}

impl AttackVector {
    pub fn value(&self) -> f32 {
        match self {
            AttackVector::Network => 0.85,
            AttackVector::Adjacent => 0.62,
            AttackVector::Local => 0.55,
            AttackVector::Physical => 0.2,
        }
    }
}

impl AttackComplexity {
    pub fn value(&self) -> f32 {
        match self {
            AttackComplexity::Low => 0.77,
            AttackComplexity::High => 1.22,
        }
    }
}

impl PrivilegesRequired {
    pub fn value(&self, scope: &Scope) -> f32 {
        match self {
            PrivilegesRequired::None => 0.85,
            PrivilegesRequired::Low => match scope {
                Scope::Unchanged => 0.62,
                Scope::Changed => 0.5,
            },
            PrivilegesRequired::High => match scope {
                Scope::Unchanged => 0.27,
                Scope::Changed => 0.5,
            },
        }
    }
}

impl UserInteraction {
    pub fn value(&self) -> f32 {
        match self {
            UserInteraction::None => 0.85,
            UserInteraction::Required => 0.62,
        }
    }
}