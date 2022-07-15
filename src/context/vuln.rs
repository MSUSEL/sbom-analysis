use std::collections::BTreeMap;

use crate::{cvss, v3_1};
use crate::cvss::FromVector;
use crate::format::grype;

pub trait CvssProvider {
    fn cvss_v3_1(&self) -> Option<v3_1::BaseMetric>;
}

impl<T: CvssProvider> CvssProvider for &T {
    fn cvss_v3_1(&self) -> Option<v3_1::BaseMetric> {
        (*self).cvss_v3_1()
    }
}

impl CvssProvider for grype::Vulnerability {
    fn cvss_v3_1(&self) -> Option<v3_1::BaseMetric> {
        self.cvss.iter()
            .filter(|cvss| cvss.version == "3.1")
            .map(|cvss| cvss.vector.split('/'))
            .filter_map(|mut v| {
                v.next(); // Skip the version
                let map = BTreeMap::from_iter(v
                    .map(|v| v.split(':'))
                    .map(|mut v| (v.next(), v.next()))
                    .filter_map(|(a, b)| a.and_then(|a| b.map(|b| (a, b))))
                );

                use cvss::v3_1::*;

                BaseMetric::from_vector(&map)
            }).next()
    }
}