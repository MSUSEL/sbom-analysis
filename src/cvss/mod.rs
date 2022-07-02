#![allow(dead_code)]

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

#[cfg(test)]
mod tests {
    use crate::cvss::*;

    #[test]
    fn base_score_1() {
        let metric = BaseMetric {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::High,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::Required,
            scope: Scope::Unchanged,
            confidentiality_impact: ImpactValue::Low,
            integrity_impact: ImpactValue::None,
            availability_impact: ImpactValue::Low,
        };

        assert_eq!(metric.score(), 4.2);
    }

    #[test]
    fn base_score_2() {
        let metric = BaseMetric {
            attack_vector: AttackVector::Local,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::Low,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: ImpactValue::Low,
            integrity_impact: ImpactValue::High,
            availability_impact: ImpactValue::High,
        };

        assert_eq!(metric.score(), 7.3);
    }

    #[test]
    fn base_score_3() {
        let metric = BaseMetric {
            attack_vector: AttackVector::Local,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::Low,
            user_interaction: UserInteraction::None,
            scope: Scope::Changed,
            confidentiality_impact: ImpactValue::Low,
            integrity_impact: ImpactValue::High,
            availability_impact: ImpactValue::High,
        };

        assert_eq!(metric.score(), 8.7);
    }
}