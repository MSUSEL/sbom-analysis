#[derive(Debug, Clone, PartialEq, Ord, PartialOrd, Eq)]
pub enum CvssVersion {
    V2_0,
    V3_0,
    V3_1,
}

pub trait Cvss {
    fn version(&self) -> Option<CvssVersion>;
    fn vector(&self) -> Option<String>;

    fn as_vector(&self) -> Option<CvssVector> {
        self.version().zip(self.vector())
            .map(|(version, vector)| CvssVector {
                version,
                vector,
            })
    }
}

impl<T: Cvss + Sized> TryInto<CvssVector> for (T, ) {
    type Error = ();

    fn try_into(self) -> Result<CvssVector, Self::Error> {
        let version = self.0.version();
        let vector = self.0.vector();
        version.zip(vector)
            .map(|(version, vector)| {
                CvssVector {
                    version,
                    vector,
                }
            })
            .ok_or(())
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct CvssVector {
    pub version: CvssVersion,
    pub vector: String,
}