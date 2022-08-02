
# Scayl (Library)
The Scayl library is a rust library that can be used to analyze the vulnerabilities found inside a variety of
different vulnerability report formats.

Documentation can be found [here](https://msusel.github.io/sbom-analysis/scayl/index.html).

### Cargo Features
This library comes with 6 unique features and 8 total features.

 - **default**: The default feature-set when using this crate in a cargo project  
`default=["full"]`
 
 - **full**: The full feature-set when using this crate in a cargo project   
`full = ["grype", "syft", "trivy", "sarif", "nvd", "cyclonedx"]`  
 - **grype**: Provides the grype format and vulnerability trait implementations   
 `grype = []`  
 - **syft**: Provides the syft format and vulnerability trait implementations   
 `syft = []`  
 - **trivy**: Provides the trivy format and vulnerability trait implementations   
 `trivy = []`  
 - **sarif**: Provides the sarif format and vulnerability trait implementations   
 `sarif = []`  
 - **nvd**: Provides the nvd format and vulnerability trait implementations   
 `nvd = []`  
 - **cyclonedx**: Provides the cyclonedx format and vulnerability trait implementations   
 `cyclonedx = []`  
