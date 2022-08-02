#[derive(Debug, Clone, PartialEq, Ord, PartialOrd, Eq)]
pub enum CvssVersion {
    V2_0,
    V3_0,
    V3_1,
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct CvssVector {
    pub version: CvssVersion,
    pub vector: String,
}

/// A CVSS abstract
pub trait Cvss {
    /// The version of this cvss value
    fn version(&self) -> Option<CvssVersion>;

    /// The cvss vector of this cvss value
    fn vector(&self) -> Option<String>;

    /// The cvss vector of this cvss value
    fn as_vector(&self) -> Option<CvssVector> {
        self.version().zip(self.vector())
            .map(|(version, vector)| CvssVector {
                version,
                vector,
            })
    }
}

impl<T: Cvss> Cvss for &T {
    fn version(&self) -> Option<CvssVersion> {
        (*self).version()
    }
    fn vector(&self) -> Option<String> {
        (*self).vector()
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