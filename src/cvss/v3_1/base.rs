cvss_component!(AttackVector {
    Network => N,
    Adjacent => A,
    Local => L,
    Physical => P,
});

cvss_component!(AttackComplexity {
    Low => L,
    High => H,
});

cvss_component!(PrivilegesRequired {
    None => N,
    Low => L,
    High => H,
});

cvss_component!(UserInteraction {
    None => N,
    Required => R,
});

cvss_component!(Scope {
    Unchanged => U,
    Changed => C,
});

cvss_component!(ImpactMetric {
    None => N,
    Low => L,
    High => H,
});

cvss_score!(BaseMetric => "CVSS:3.1" {
    attack_vector: AttackVector => AV,
    attack_complexity: AttackComplexity => AC,
    privileges_required: PrivilegesRequired => PR,
    user_interaction: UserInteraction => UI,
    scope: Scope => S,
    confidentiality_impact: ImpactMetric => C,
    integrity_impact: ImpactMetric => I,
    availability_impact: ImpactMetric => A,
});