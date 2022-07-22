use std::collections::BTreeMap;

use crate::cvss::v3_1;
use crate::cvss::FromVector;

/// A vulnerability of some sort
pub trait CvssProvider {
    fn cvss_v3_1(&self) -> Option<v3_1::BaseMetric>;
}

impl<T: CvssProvider> CvssProvider for &T {
    fn cvss_v3_1(&self) -> Option<v3_1::BaseMetric> {
        (*self).cvss_v3_1()
    }
}