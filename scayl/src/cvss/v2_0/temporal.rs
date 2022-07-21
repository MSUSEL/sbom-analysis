

cvss_component!(Exploitability {
    Unproven => U,
    ProofOfConcept => POC,
    Functional => F,
    High => H,
    NotDefined => ND,
});

cvss_component!(RemediationLevel {
    OfficialFix => OF,
    TemporaryFix => TF,
    Workaround => W,
    Unavailable => U,
    NotDefined => ND,
});

cvss_component!(ReportConfidence {
    Unconfirmed => UC,
    Uncorroborated => UR,
    Confirmed => C,
    NotDefined => ND,
});

cvss_score!(TemporalMetric {
    exploitability: Exploitability => E,
    remediation_level: RemediationLevel => RL,
    report_confidence: ReportConfidence => RC,
});
