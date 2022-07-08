use std::collections::BTreeMap;
use crate::cvss::FromVector;
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

impl BaseMetric {
    pub fn from_vector_string(val: &str) -> Option<Self> {
        let iter = val.split('/');
        let map = BTreeMap::from_iter(iter
            .map(|v| {
                let mut iter = v.split(':');
                (iter.next(), iter.next())
            })
            .filter_map(|(a, b)| a.and_then(|a| b.map(|b| (a, b)))));
        Self::from_vector(&map)
    }
}