use super::BaseMetric;
use super::roundup;

pub struct TemporalMetric {
    pub exploit_code_maturity: ExploitCodeMaturity,
    pub remediation_level: RemediationLevel,
    pub report_confidence: ReportConfidence,
}

pub enum ExploitCodeMaturity {
    NotDefined,
    High,
    Functional,
    ProofOfConcept,
    Unproven,
}

pub enum RemediationLevel {
    NotDefined,
    Unavailable,
    Workaround,
    TemporaryFix,
    OfficialFix,
}

pub enum ReportConfidence {
    NotDefined,
    Confirmed,
    Reasonable,
    Unknown,
}

impl TemporalMetric {
    pub fn score(&self, base: &BaseMetric) -> f32 {
        roundup(base.score()
         * self.exploit_code_maturity.value()
        * self.remediation_level.value()
        * self.report_confidence.value())
    }
}

impl ExploitCodeMaturity {
    pub fn value(&self) -> f32 {
        match self {
            ExploitCodeMaturity::NotDefined | ExploitCodeMaturity::High => 1.0,
            ExploitCodeMaturity::Functional => 0.97,
            ExploitCodeMaturity::ProofOfConcept => 0.94,
            ExploitCodeMaturity::Unproven => 0.91,
        }
    }
}

impl RemediationLevel {
    pub fn value(&self) -> f32 {
        match self {
            RemediationLevel::NotDefined | RemediationLevel::Unavailable => 1.0,
            RemediationLevel::Workaround => 0.97,
            RemediationLevel::TemporaryFix => 0.96,
            RemediationLevel::OfficialFix => 0.95,
        }
    }
}

impl ReportConfidence {
    pub fn value(&self) -> f32 {
        match self {
            ReportConfidence::NotDefined | ReportConfidence::Confirmed => 1.0,
            ReportConfidence::Reasonable => 0.96,
            ReportConfidence::Unknown => 0.92,
        }
    }
}