use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, LinkedList};

use crate::context::{DeploymentContext, DeploymentWeight, score_cvss};
use crate::cvss::v3_1::BaseMetric;
use crate::format::grype::Grype;
use crate::format::trivy::{TrivyCvss, TrivyJson};
use crate::Syft;

pub struct ContextRunner<'a> {
    grype: Vec<&'a Grype>,
    syft: Vec<&'a Syft>,
    trivy: Vec<&'a TrivyJson>,
}

#[derive(Debug, Clone)]
pub struct DeploymentScore {
    pub score: f32,
    pub network: f32,
    pub files: f32,
    pub remote: f32,
    pub information: f32,
    pub permissions: f32,
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

    pub fn trivy(&mut self, trivy: &'a TrivyJson) -> &mut Self {
        self.trivy.push(trivy);
        self
    }

    pub fn calculate(&self,
                     context: &DeploymentContext,
                     weights: &DeploymentWeight,
    ) -> Option<DeploymentScore> {
        // let mut scores = self.calculate_grype::<Vec<_>>(context, weights);
        // scores.extend(self.calculate_trivy::<Vec<_>>(context, weights));

        let mut cvss_scores = BTreeMap::new();

        self.trivy.iter()
            .flat_map(|v| v.results.iter())
            .filter_map(|v| v.vulnerabilities.as_ref())
            .flatten()
            .filter_map(|v| {
                let id = v.cve_id();
                let res = v.cvss.as_ref()
                    .and_then(|v| v.nvd.as_ref().or(v.redhat.as_ref()))
                    .and_then(|v| v.v3_vector.as_ref());

                id.zip(res)
            })
            .for_each(|(id, cvss)| {
                cvss_scores.entry(id).or_insert_with(|| LinkedList::new())
                    .push_back(cvss);
            });

        self.grype.iter()
            .flat_map(|v| v.matches.iter())
            .map(|v| &v.vulnerability)
            .map(|v| {
                let list = v.cvss.iter()
                    .filter(|v| v.version == "3.1");
                (v.id.clone(), list)
            })
            .for_each(|(k, v)| {
                cvss_scores.entry(k).or_insert_with(|| LinkedList::new())
                    .push_back(v)
            });

        None
    }

    fn calculate_trivy<T: FromIterator<f32>>(
        &self,
        ctx: &DeploymentContext,
        weights: &DeploymentWeight,
    ) -> T {
        self.trivy.iter()
            .map(|v| v.results.iter())
            .map(|v| {
                v.filter_map(|v| v.vulnerabilities.as_ref())
                    .filter_map(|v| {
                        v.iter()
                            .find_map(|v| {
                                let v = v.cvss.as_ref()?;
                                let v = v.nvd.as_ref().or(v.redhat.as_ref())?;
                                let v = v.v3_vector.as_ref()?;
                                BaseMetric::from_vector_string(&v)
                            })
                    })
                    .map(|v| score_cvss(ctx, weights, &v))
            })
            .flatten()
            .collect::<T>()
    }

    fn calculate_grype<T: FromIterator<f32>>(
        &self,
        ctx: &DeploymentContext,
        weights: &DeploymentWeight,
    ) -> T {
        self.grype.iter()
            .filter_map(|v| {
                v.matches.iter()
                    .map(|v| &v.vulnerability)
                    .filter_map(|v| {
                        v.cvss
                            .iter()
                            .filter(|v| v.version == "3.1")
                            .filter_map(|v| BaseMetric::from_vector_string(&v.vector))
                            .next()
                    })
                    .map(|v| score_cvss(ctx, weights, &v))
                    .next()
            })
            .collect()
    }
}