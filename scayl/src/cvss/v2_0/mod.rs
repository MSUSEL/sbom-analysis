pub use base::*;
pub use environmental::*;
pub use temporal::*;

mod base;
mod temporal;
mod environmental;

fn round1(v: f32) -> f32 {
    (v * 10.0).round() / 10.0
}

impl BaseMetric {
    pub fn scores(&self) -> (f32, f32, f32) {
        let impact = self.impact_score();
        let exploitability = self.exploitability_score();
        let raw = (0.6 * impact) + (0.4 * exploitability) - 1.5;
        if impact <= 0f32 {
            (0.0, 0.0, round1(exploitability))
        } else {
            (round1(1.176 * raw), round1(impact), round1(exploitability))
        }
    }

    pub fn base_score(&self) -> f32 {
        let v = (0.6 * self.impact_score()) + (0.4 * self.exploitability_score()) - 1.5;
        round1(self.f_impact_score() * v)
    }

    pub fn f_impact_score(&self) -> f32 {
        if self.impact_score() <= 0f32 {
            0.0
        } else {
            1.176
        }
    }

    pub fn impact(&self) -> f32 {
        round1(self.impact_score())
    }

    pub fn exploitability(&self) -> f32 {
        round1(self.exploitability_score())
    }

    fn impact_score(&self) -> f32 {
        let v = (1.0 - self.confidentiality_impact_score())
            * (1.0 - self.integrity_impact_score())
            * (1.0 - self.availability_impact_score());
        10.41 * (1.0 - v)
    }

    fn exploitability_score(&self) -> f32 {
        20.0 * self.access_vector_score()
            * self.access_complexity_score()
            * self.authentication_score()
    }

    fn access_vector_score(&self) -> f32 {
        match self.access_vector {
            AccessVector::Local => 0.395,
            AccessVector::AdjacentNetwork => 0.646,
            AccessVector::Network => 1.0,
        }
    }

    fn access_complexity_score(&self) -> f32 {
        match self.access_complexity {
            AccessComplexity::High => 0.35,
            AccessComplexity::Medium => 0.61,
            AccessComplexity::Low => 0.71,
        }
    }

    fn authentication_score(&self) -> f32 {
        match self.authentication {
            Authentication::None => 0.704,
            Authentication::Single => 0.56,
            Authentication::Multiple => 0.45,
        }
    }

    fn confidentiality_impact_score(&self) -> f32 {
        match self.confidentiality_impact {
            Impact::None => 0f32,
            Impact::Partial => 0.275,
            Impact::Complete => 0.660,
        }
    }

    fn integrity_impact_score(&self) -> f32 {
        match self.integrity_impact {
            Impact::None => 0f32,
            Impact::Partial => 0.275,
            Impact::Complete => 0.660,
        }
    }

    fn availability_impact_score(&self) -> f32 {
        match self.availability_impact {
            Impact::None => 0f32,
            Impact::Partial => 0.275,
            Impact::Complete => 0.660,
        }
    }
}

impl TemporalMetric {
    pub fn temporal_score(&self, base_score: f32) -> f32 {
        round1(base_score * self.exploitability() * self.remediation_level() * self.report_confidence())
    }

    fn exploitability(&self) -> f32 {
        match self.exploitability {
            Exploitability::Unproven => 0.85,
            Exploitability::ProofOfConcept => 0.9,
            Exploitability::Functional => 0.95,
            Exploitability::High | Exploitability::NotDefined => 1.00,
        }
    }

    fn remediation_level(&self) -> f32 {
        match self.remediation_level {
            RemediationLevel::OfficialFix => 0.87,
            RemediationLevel::TemporaryFix => 0.90,
            RemediationLevel::Workaround => 0.95,
            RemediationLevel::Unavailable | RemediationLevel::NotDefined => 1.00,
        }
    }

    fn report_confidence(&self) -> f32 {
        match self.report_confidence {
            ReportConfidence::Unconfirmed => 0.90,
            ReportConfidence::Uncorroborated => 0.95,
            ReportConfidence::Confirmed | ReportConfidence::NotDefined => 1.00,
        }
    }
}

impl EnvironmentMetric {
    pub fn environmental_score(&self, metric: &BaseMetric) -> f32 {
        let adjusted_temporal = self.adjusted_temporal(metric);
        let val = adjusted_temporal + (10.0 - adjusted_temporal) * self.collateral_damage_potential();
        round1(val * self.target_distribution())
    }

    pub fn adjusted_temporal(&self, _metric: &BaseMetric) -> f32 {
        // TemporalScore recomputed with the BaseScore's Impact sub-
        //   equation replaced with the AdjustedImpact equation
        // 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
        todo!("adjusted_temporal")
    }

    fn adjusted_impact(&self, metric: &BaseMetric) -> f32 {
        let val = {
            let a = 1.0 - self.confidentiality_requirement() * metric.confidentiality_impact_score();
            let b = 1.0 - self.integrity_requirement() * metric.integrity_impact_score();
            let c = 1.0 - self.availability_requirement() * metric.availability_impact_score();
            1.0 - a * b * c
        } * 10.41;
        round1(val.min(10f32))
    }

    fn collateral_damage_potential(&self) -> f32 {
        match self.collateral_damage_potential {
            CollateralDamagePotential::None | CollateralDamagePotential::NotDefined => 0.0,
            CollateralDamagePotential::Low => 0.1,
            CollateralDamagePotential::LowMedium => 0.3,
            CollateralDamagePotential::MediumHigh => 0.4,
            CollateralDamagePotential::High => 0.5,
        }
    }

    fn target_distribution(&self) -> f32 {
        match self.target_distribution {
            TargetDistribution::None => 0.0,
            TargetDistribution::Low => 0.25,
            TargetDistribution::Medium => 0.75,
            TargetDistribution::High | TargetDistribution::NotDefined => 1.00,
        }
    }

    fn confidentiality_requirement(&self) -> f32 {
        match self.confidentiality_requirement {
            SecurityRequirement::Low => 0.5,
            SecurityRequirement::Medium => 1.0,
            SecurityRequirement::High => 1.51,
            SecurityRequirement::NotDefined => 1.0,
        }
    }

    fn integrity_requirement(&self) -> f32 {
        match self.integrity_requirement {
            SecurityRequirement::Low => 0.5,
            SecurityRequirement::Medium => 1.0,
            SecurityRequirement::High => 1.51,
            SecurityRequirement::NotDefined => 1.0,
        }
    }

    fn availability_requirement(&self) -> f32 {
        match self.availability_requirement {
            SecurityRequirement::Low => 0.5,
            SecurityRequirement::Medium => 1.0,
            SecurityRequirement::High => 1.51,
            SecurityRequirement::NotDefined => 1.0,
        }
    }
}