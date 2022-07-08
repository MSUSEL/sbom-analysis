use std::collections::BTreeMap;

use crate::context::{DeploymentContext, DeploymentScore, DeploymentWeight, score_cvss};
use crate::format::grype::Grype;
use crate::format::trivy::TrivyJson;
use crate::model::{Cvss, CvssVector, CvssVersion};
use crate::Syft;
use crate::cvss::{v2_0, v3_1};

pub struct ContextRunner<'a> {
    grype: Vec<&'a Grype>,
    syft: Vec<&'a Syft>,
    trivy: Vec<&'a TrivyJson>,
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
    ) -> (DeploymentScore, u32) {
        // let mut scores = self.calculate_grype::<Vec<_>>(context, weights);
        // scores.extend(self.calculate_trivy::<Vec<_>>(context, weights));

        let trivy = self.trivy
            .iter()
            .flat_map(|v| v.results.iter())
            .filter_map(|v| v.vulnerabilities.as_ref())
            .flatten()
            .filter_map(|v| v.cve_id().zip(v.cvss.as_ref()))
            .filter_map(|(id, vec)| vec.as_vector().map(|v| (id, v)));

        let grype = self.grype
            .iter()
            .flat_map(|v| v.matches.iter())
            .map(|v| &v.vulnerability)
            .filter(|v| !v.cvss.is_empty())
            .filter_map(|v| v.cve_id().map(|id| {
                let iter = v.cvss.iter()
                    .filter(|v| v.version == "3.1");
                (id, iter)
            }))
            .flat_map(|(id, iter)| {
                iter.map(move |v| (id.clone(), v.clone()))
            })
            .filter_map(|(k, v)| {
                v.as_vector().map(|v| (k, v))
            });

        fn group(
            iter: impl Iterator<Item=(String, CvssVector)>,
            map: &mut BTreeMap<String, BTreeMap<CvssVector, u32>>,
        ) {
            iter.for_each(|(key, cvss)| {
                let entry = map.entry(key)
                    .or_insert_with(|| BTreeMap::new());
                let count = entry.entry(cvss).or_insert(0u32);
                *count += 1;
            })
        }

        let mut cvss_scores = BTreeMap::new();
        group(trivy, &mut cvss_scores);
        group(grype, &mut cvss_scores);

        let mut sum = DeploymentScore::default();
        let mut total = 0u32;
        for (_, scores) in cvss_scores {
            for (score, count) in &scores {
                match score.version {
                    CvssVersion::V2_0 => {
                        let _metric = v2_0::BaseMetric::from_vector_string(&score.vector);
                        todo!("Score metric")
                    }
                    CvssVersion::V3_0 => continue,
                    CvssVersion::V3_1 => {
                        let metric = v3_1::BaseMetric::from_vector_string(&score.vector);
                        let metric = match metric {
                            None => continue,
                            Some(v) => v,
                        };
                        let score = score_cvss(context, weights, &metric);
                        let val = *count as f32;
                        let v = score * val;
                        sum += v;
                    }
                };
                total += 5 * *count;
            }
        }

        (sum, total)
    }
}