use std::collections::{BTreeMap, LinkedList};
use std::collections::btree_map::Entry;
use std::fmt::{Display, Formatter};

use crate::{ScaylInfo, VulnerabilityFormat, VulnerabilityScore};
use crate::context::{DeploymentContext, DeploymentScore};
use crate::cvss::{FromVector, v3_1};
#[cfg(feature = "cyclonedx")]
use crate::format::cyclonedx::CycloneDx;
#[cfg(feature = "grype")]
use crate::format::grype::Grype;
#[cfg(feature = "syft")]
use crate::format::syft::Syft;
#[cfg(feature = "trivy")]
use crate::format::trivy::Trivy;
use crate::format::VulnId;
use crate::v3_1::BaseMetric;

pub struct ContextRunner<'a> {
    #[cfg(feature = "grype")]
    grype: Vec<&'a Grype>,
    #[cfg(feature = "syft")]
    syft: Vec<&'a Syft>,
    #[cfg(feature = "trivy")]
    trivy: Vec<&'a Trivy>,
    #[cfg(feature = "cyclonedx")]
    cyclone_dx: Vec<&'a CycloneDx>,
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
            #[cfg(feature = "grype")]
            grype: Default::default(),
            #[cfg(feature = "trivy")]
            trivy: Default::default(),
            #[cfg(feature = "syft")]
            syft: Default::default(),
            #[cfg(feature = "cyclonedx")]
            cyclone_dx: Default::default(),
        }
    }

    #[cfg(feature = "grype")]
    pub fn grype(&mut self, grype: &'a Grype) -> &mut Self {
        self.grype.push(grype);
        self
    }

    #[cfg(feature = "trivy")]
    pub fn trivy(&mut self, trivy: &'a Trivy) -> &mut Self {
        self.trivy.push(trivy);
        self
    }

    #[cfg(feature = "syft")]
    pub fn syft(&mut self, syft: &'a Syft) -> &mut Self {
        self.syft.push(syft);
        self
    }

    #[cfg(feature = "cyclonedx")]
    pub fn cyclone_dx(&mut self, cyclonedx: &'a CycloneDx) -> &mut Self {
        self.cyclone_dx.push(cyclonedx);
        self
    }

    pub fn calculate(&self,
                     context: &DeploymentContext,
    ) -> Result<DeploymentScore, LinkedList<Error>> {
        // let mut scores = self.calculate_grype::<Vec<_>>(context, weights);
        // scores.extend(self.calculate_trivy::<Vec<_>>(context, weights));

        fn group(
            iter: impl Iterator<Item=BTreeMap<VulnId, v3_1::BaseMetric>>,
            map: &mut BTreeMap<VulnId, v3_1::BaseMetric>,
        ) -> Result<(), LinkedList<Error>> {
            let mut errs = LinkedList::new();
            for set in iter {
                for (id, metric) in set.into_iter() {
                    match map.entry(id) {
                        Entry::Vacant(entry) => {
                            entry.insert(metric);
                        }
                        Entry::Occupied(entry) => {
                            if *entry.get() != metric {
                                errs.push_back(Error::DifferingCvssScore {
                                    id: entry.key().clone(),
                                    existing: entry.get().clone(),
                                    new: metric,
                                });
                            };
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


        fn merge_name(name: &mut Option<String>, val: String) -> Option<()> {
            if let Some(n) = name {
                if *n != val {
                    None
                } else {
                    Some(())
                }
            } else {
                *name = Some(val);
                Some(())
            }
        }

        let mut name = None;
        let mut cvss_scores = BTreeMap::new();
        #[cfg(feature = "trivy")] {
            let trivy = self.trivy
                .iter()
                .map(|v| {
                    merge_name(&mut name, v.artifact_name.clone())
                        .expect("Component name should be the same for all artifacts");
                    v.cvss_v3_1_scores()
                });

            group(trivy, &mut cvss_scores)?;
        }
        #[cfg(feature = "grype")] {
            let grype = self.grype
                .iter()
                .map(|v| {
                    merge_name(&mut name, v.source.target.user_input.clone())
                        .expect("Component name should be the same for all artifacts");
                    v.cvss_v3_1_scores()
                });
            group(grype, &mut cvss_scores)?;
        }
        #[cfg(feature = "cyclonedx")] {
            let cyclonedx = self.cyclone_dx
                .iter()
                .map(|v| {
                    merge_name(&mut name, v.metadata.component.name.clone())
                        .expect("Component name should be the same for all artifacts");
                    v.cvss_v3_1_scores()
                });
            group(cyclonedx, &mut cvss_scores)?;
        }

        let scores = cvss_scores.into_iter().map(|(k, v)| {
            let score = context.score_v3(&v);
            (k, score)
        }).collect::<BTreeMap<_, _>>();

        Ok(DeploymentScore {
            context: context.clone(),
            scayl: ScaylInfo::current(),
            source: name.unwrap_or(String::from("Unknown")),
            cumulative: scores.iter()
                .fold(VulnerabilityScore::default(), |acc, (_, v)| acc + v),
            scores,
        })
    }
}