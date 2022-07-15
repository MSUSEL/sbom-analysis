use std::collections::{BTreeMap, LinkedList};
use std::fmt::{Display, Formatter};

use crate::context::{DeploymentContext, DeploymentScore};
use crate::format::grype::Grype;
use crate::format::trivy::Trivy;
use crate::{Syft, VulnerabilityFormat};
use crate::cvss::v3_1;
use crate::format::VulnId;

pub struct ContextRunner<'a> {
    grype: Vec<&'a Grype>,
    syft: Vec<&'a Syft>,
    trivy: Vec<&'a Trivy>,
}

#[derive(Debug)]
pub enum Error {
    DifferingCvssScore { id: VulnId, existing: v3_1::BaseMetric, new: v3_1::BaseMetric },
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::DifferingCvssScore { id, existing, new } =>
                write!(f, "Conflicting CVSS scores for {}: {} vs {}", id,
                       existing.cvss_vector(),
                       new.cvss_vector(),
                )
        }
    }
}

impl<'a> ContextRunner<'a> {
    pub fn new() -> Self {
        ContextRunner {
            grype: Default::default(),
            syft: Default::default(),
            trivy: Default::default(),
        }
    }

    pub fn syft(&mut self, syft: &'a Syft) -> &mut Self {
        self.syft.push(syft);
        self
    }

    pub fn grype(&mut self, grype: &'a Grype) -> &mut Self {
        self.grype.push(grype);
        self
    }

    pub fn trivy(&mut self, trivy: &'a Trivy) -> &mut Self {
        self.trivy.push(trivy);
        self
    }

    pub fn calculate(&self,
                     context: &DeploymentContext
    ) -> Result<DeploymentScore, LinkedList<Error>> {
        // let mut scores = self.calculate_grype::<Vec<_>>(context, weights);
        // scores.extend(self.calculate_trivy::<Vec<_>>(context, weights));

        let trivy = self.trivy
            .iter()
            .map(|v| v.cvss_v3_1_scores());

        let grype = self.grype
            .iter()
            .map(|v| v.cvss_v3_1_scores());

        fn group(
            iter: impl Iterator<Item=BTreeMap<VulnId, v3_1::BaseMetric>>,
            map: &mut BTreeMap<VulnId, v3_1::BaseMetric>,
        ) -> Result<(), LinkedList<Error>> {
            let mut errs = LinkedList::new();
            for set in iter {
                for (id, metric) in set.into_iter() {
                    if let Some(entry) = map.get(&id) {
                        if *entry != metric {
                            errs.push_back(Error::DifferingCvssScore {
                                id,
                                existing: entry.clone(),
                                new: metric,
                            });
                        }
                    }
                }
            }
            if !errs.is_empty() {
                Err(errs)
            } else {
                Ok(())
            }
        }

        let mut cvss_scores = BTreeMap::new();
        group(trivy, &mut cvss_scores)?;
        group(grype, &mut cvss_scores)?;

        let scores = cvss_scores.into_iter().map(|(k, v)| {
            let score = context.score_v3(&v);
            (k, score)
        }).collect::<BTreeMap<_, _>>();
        Ok(DeploymentScore {
            scores,
        })
    }
}