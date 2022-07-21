mod v2_0 {
    use crate::cvss::v2_0::*;

    #[test]
    fn random_spec_1() {
        let metric = BaseMetric {
            access_vector: AccessVector::Network,
            access_complexity: AccessComplexity::High,
            authentication: Authentication::Single,
            confidentiality_impact: Impact::Partial,
            integrity_impact: Impact::None,
            availability_impact: Impact::Partial,
        };
        let (score, impact, exploitability) = metric.scores();
        assert_eq!(score, 3.6);
        assert_eq!(impact, 4.9);
        assert_eq!(exploitability, 3.9);
    }

    #[test]
    fn random_spec_2() {
        let metric = BaseMetric {
            access_vector: AccessVector::Local,
            access_complexity: AccessComplexity::Medium,
            authentication: Authentication::Multiple,
            confidentiality_impact: Impact::None,
            integrity_impact: Impact::None,
            availability_impact: Impact::None,
        };
        let (base, impact, exploitability) = metric.scores();
        assert_eq!(base, 0.0);
        assert_eq!(impact, 0.0);
        assert_eq!(exploitability, 2.2);
    }
}


#[cfg(test)]
mod tests {
    use crate::cvss::v3_1::*;

    #[test]
    fn base_score_1() {
        let metric = BaseMetric {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::High,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::Required,
            scope: Scope::Unchanged,
            confidentiality_impact: ImpactMetric::Low,
            integrity_impact: ImpactMetric::None,
            availability_impact: ImpactMetric::Low,
        };

        assert_eq!(metric.base_score(), 4.2);
    }

    #[test]
    fn base_score_2() {
        let metric = BaseMetric {
            attack_vector: AttackVector::Local,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::Low,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: ImpactMetric::Low,
            integrity_impact: ImpactMetric::High,
            availability_impact: ImpactMetric::High,
        };

        assert_eq!(metric.base_score(), 7.3);
    }

    #[test]
    fn base_score_3() {
        let metric = BaseMetric {
            attack_vector: AttackVector::Local,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::Low,
            user_interaction: UserInteraction::None,
            scope: Scope::Changed,
            confidentiality_impact: ImpactMetric::Low,
            integrity_impact: ImpactMetric::High,
            availability_impact: ImpactMetric::High,
        };

        assert_eq!(metric.base_score(), 8.7);
    }
}