cvss_component!(AccessVector {
    Local => L,
    AdjacentNetwork => A,
    Network => N,
});

cvss_component!(AccessComplexity {
    High => H,
    Medium => M,
    Low => L,
});

cvss_component!(Authentication {
    Multiple => M,
    Single => S,
    None => N,
});

cvss_component!(Impact {
    None => N,
    Partial => P,
    Complete => C,
});

cvss_score!(BaseMetric {
    access_vector: AccessVector => AV,
    access_complexity: AccessComplexity => AC,
    authentication: Authentication => Au,
    confidentiality_impact: Impact => C,
    integrity_impact: Impact => I,
    availability_impact: Impact => A,
});