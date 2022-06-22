use crate::cvss::{AttackComplexity, AttackVector, ExploitCodeMaturity, ImpactValue, PrivilegesRequired, RemediationLevel, ReportConfidence, roundup, Scope, UserInteraction};

pub enum Requirement {
    NotDefined,
    High,
    Medium,
    Low,
}

impl Requirement {
    fn score(&self) -> f32 {
        match self {
            Requirement::NotDefined => 1.0,
            Requirement::High => 1.5,
            Requirement::Medium => 1.0,
            Requirement::Low => 0.5,
        }
    }
}

pub struct EnvironmentalMetric {
    confidentiality_requirement: Requirement,
    integrity_requirement: Requirement,
    availability_requirement: Requirement,
    modified_attack_vector: AttackVector,
    modified_attack_complexity: AttackComplexity,
    modified_privileges_required: PrivilegesRequired,
    modified_user_interaction: UserInteraction,
    modified_scope: Scope,
    modified_confidentiality_impact: ImpactValue,
    modified_integrity_impact: ImpactValue,
    modified_availability_impact: ImpactValue,
}

impl EnvironmentalMetric {
    pub fn confidentiality_score(&self) -> f32 {
        self.confidentiality_requirement.score()
    }

    pub fn integrity_score(&self) -> f32 {
        self.integrity_requirement.score()
    }

    pub fn availability_score(&self) -> f32 {
        self.availability_requirement.score()
    }

    pub fn modified_impact(&self) -> f32 {
        let a = 1.0 - self.availability_score() * self.modified_confidentiality_impact.value();
        let b = 1.0 - self.integrity_score() * self.modified_integrity_impact.value();
        let c = 1.0 - self.confidentiality_score() * self.modified_availability_impact.value();
        let d = 1.0 - (a * b * c);
        let miss = d.min(0.915);
        match self.modified_scope {
            Scope::Unchanged => 6.42 * miss,
            Scope::Changed => 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02).powi(13),
        }
    }

    pub fn modified_exploitability(&self) -> f32 {
        8.22 * self.modified_attack_vector.value()
            * self.modified_attack_complexity.value()
            * self.modified_privileges_required.value(&self.modified_scope)
            * self.modified_user_interaction.value()
    }

    pub fn score(&self,
                 ecm: ExploitCodeMaturity,
                 rl: RemediationLevel,
                 rc: ReportConfidence,
    ) -> f32 {
        let modified_impact = self.modified_impact();
        if modified_impact <= 0.0 { 0.0 } else {
            let mut a = modified_impact + self.modified_exploitability();
            if let Scope::Changed = self.modified_scope {
                a *= 1.08;
            }
            let a = roundup(a.min(10.0));
            let b = ecm.value() * rl.value() * rc.value();
            roundup(a * b)
        }
    }
}