// imports cvss_component macro

cvss_component!(CollateralDamagePotential {
    None => N,
    Low => L,
    LowMedium => LM,
    MediumHigh => MH,
    High => H,
    NotDefined => ND,
});

cvss_component!(TargetDistribution {
    None => N,
    Low => L,
    Medium => M,
    High => H,
    NotDefined => ND,
});

cvss_component!(SecurityRequirement {
    Low => L,
    Medium => M,
    High => H,
    NotDefined => ND,
});

cvss_score!(EnvironmentMetric {
    collateral_damage_potential: CollateralDamagePotential => CDP,
    target_distribution: TargetDistribution => TD,
    confidentiality_requirement: SecurityRequirement => CR,
    integrity_requirement: SecurityRequirement => IR,
    availability_requirement: SecurityRequirement => AR,
});
