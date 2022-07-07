use crate::context::{DeploymentContext, DeploymentWeight, score_cvss};
use crate::cvss::v3_1::BaseMetric;
use crate::format::grype::Grype;
use crate::format::trivy::TrivyJson;
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
        let scores = self.calculate_grype(context, weights);
        println!("Scores: {:?}", scores);
        // let syft = self.calculate_syft(ctx);
        // let trivy = self.calculate_trivy(ctx);
        todo!()
    }

    fn calculate_grype(&self,
                       ctx: &DeploymentContext,
                       weights: &DeploymentWeight,
    ) -> Vec<f32> {
        self.grype.iter()
            .map(|v| {
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
            .filter_map(|v| v)
            .collect()
    }
}