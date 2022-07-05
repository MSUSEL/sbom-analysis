use std::collections::BTreeMap;
use crate::cvss::roundup;
use crate::format::grype::Cvss;

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

impl BaseMetric {
    pub fn from_grype(cvss: &Cvss) -> Option<Self> {
        let mut parts = cvss.vector.split('/').peekable();
        if parts.peek().map(|v| *v != "CVSS:3.1").unwrap_or(true) {
            return None;
        }
        parts.next();
        let values = BTreeMap::from_iter(parts.filter_map(|v| {
            println!("{}", v);
            let mut v = v.split(':');
            v.next()
                .and_then(|k| v.next().map(|v| (k, v)))
        }));
        println!("{:?}", values);
        let attack_vector = match *values.get("AV")? {
            "N" => AttackVector::Network,
            "A" => AttackVector::Adjacent,
            "L" => AttackVector::Local,
            "P" => AttackVector::Physical,
            _ => return None,
        };
        let attack_complexity = match *values.get("AC")? {
            "H" => AttackComplexity::High,
            "L" => AttackComplexity::Low,
            _ => return None,
        };
        let privileges_required = match *values.get("PR")? {
            "N" => PrivilegesRequired::None,
            "L" => PrivilegesRequired::Low,
            "H" => PrivilegesRequired::High,
            _ => return None,
        };
        let user_interaction = match *values.get("UI")? {
            "R" => UserInteraction::Required,
            "N" => UserInteraction::None,
            _ => return None,
        };
        let scope = match *values.get("S")? {
            "U" => Scope::Unchanged,
            "C" => Scope::Changed,
            _ => return None,
        };
        let confidentiality_impact = match *values.get("C")? {
            "N" => ImpactValue::None,
            "L" => ImpactValue::Low,
            "H" => ImpactValue::High,
            _ => return None,
        };
        let integrity_impact = match *values.get("I")? {
            "N" => ImpactValue::None,
            "L" => ImpactValue::Low,
            "H" => ImpactValue::High,
            _ => return None,
        };
        let availability_impact = match *values.get("A")? {
            "N" => ImpactValue::None,
            "L" => ImpactValue::Low,
            "H" => ImpactValue::High,
            _ => return None,
        };
        Some(BaseMetric {
            attack_vector,
            attack_complexity,
            privileges_required,
            user_interaction,
            scope,
            confidentiality_impact,
            integrity_impact,
            availability_impact,
        })
    }
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
            AttackComplexity::High => 0.44,
        }
    }
}

impl PrivilegesRequired {
    pub fn value(&self, scope: &Scope) -> f32 {
        match self {
            PrivilegesRequired::None => 0.85,
            PrivilegesRequired::Low => match scope {
                Scope::Unchanged => 0.62,
                Scope::Changed => 0.68,
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