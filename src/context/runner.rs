use crate::context::{DeploymentContext, score_cvss};
use crate::cvss::v3_1::BaseMetric;
use crate::format::grype::Grype;
use crate::format::trivy::TrivyJson;
use crate::Syft;

pub struct ContextRunner<'a> {
    grype: Option<&'a Grype>,
    syft: Option<&'a Syft>,
    trivy: Option<&'a TrivyJson>,
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
            grype: None,
            syft: None,
            trivy: None,
        }
    }

    pub fn syft(mut self, syft: &'a Option<Syft>) -> Self {
        if let Some(syft) = syft {
            let _ = self.syft.insert(syft);
        }
        self
    }

    pub fn grype(mut self, grype: &'a Option<Grype>) -> Self {
        if let Some(grype) = grype {
            let _ = self.grype.insert(grype);
        }
        self
    }

    pub fn trivy(mut self, trivy: &'a Option<TrivyJson>) -> Self {
        if let Some(trivy) = trivy {
            let _ = self.trivy.insert(trivy);
        }
        self
    }

    pub fn calculate(&self, ctx: &DeploymentContext) -> Option<DeploymentScore> {
        let grype = self.calculate_grype(ctx);
        if let Some(scores) = grype {
            println!("Scores: {:?}", scores);
        }
        // let syft = self.calculate_syft(ctx);
        // let trivy = self.calculate_trivy(ctx);
        todo!()
    }

    fn calculate_grype(&self, ctx: &DeploymentContext) -> Option<Vec<f32>> {
        self.grype.map(|file|
            file.matches.iter()
                .map(|v| &v.vulnerability)
                .filter_map(|v| {
                    v.cvss
                        .iter()
                        .filter(|v| v.version == "3.1")
                        .filter_map(|v| BaseMetric::from_vector_string(&v.vector))
                        .next()
                })
                .map(|v| score_cvss(ctx, &v))
                .collect()
        )
    }
}