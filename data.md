### Format Information Record

| Format    | CVE ID | Vuln | Components | CWE | License | CVSS      |
|-----------|--------|------|------------|-----|---------|-----------|
| Grype     | Yes    | Yes  | No         | No  | Yes     | Yes       |
| Syft      | No     | No   | Yes        | No  | Yes     | No        |
| SPDX      | No     | No   | Yes        | No  | Yes     | No        |
| CycloneDX | No     | No   | Yes        | No  | Yes     | No        |
| Trivy     | Yes    | Yes  | No         | Yes | Yes     | Yes       |
| Sarif     | Yes    | Yes  | No         | No  | Yes     | No        |

### Tool Output Information

| Tool  | Sarif | SPDX | CycloneDX |
|-------|-------|------|-----------|
| Grype | Yes   | No   | No        |
| Syft  | No    | Yes  | Yes       |
| Trivy | Yes   | Yes  | Yes       |

### Measurable Information

##### _CVSS_

| Component              | Description                                                          | Value                                                               |
|------------------------|----------------------------------------------------------------------|---------------------------------------------------------------------|
| Attack Vector          | The surface on which an attack can be committed                      | Can be modified based on deployment environment                     |
| Attack Complexity      | The experience or information required to carry out an attack        | Can be mitigated by having little opportunity to access the service |
| Privileges Required    | The credentials & privileges required to carry out an attack         | Can be mitigated by only giving required perms                      |
| User Interaction       | Whether or not user interaction is required                          | Can it be exploited by a worm? Automated deployments may be at risk |
| Scope                  | If the service has the potential to compromise/attack other services | Can be mitigated using least access policies                        |
| Confidentiality Impact | Effect of the attack on the control of the service                   | No value                                                            |
| Integrity Impact       | Effect of the attack on sensitive/important files                    | Can be mitigated using least access policies                        |
| Availability Impact    | Effect of the attack on the health of the service                    | No value                                                            |

##### Concerns & Pitfalls
1) The tools do not detect the presence of all child projects, only the artifacts of a very select group of project types.
   - This means that deployment context cannot be accurately applied to subcomponents.
   - This is a limitation of the tools. SBOMs created by hand would be more accurate.
   - This prevents a "tree-based" approach to the analysis. Instead, we must use "heap-based" where we take into
     account the dependencies of every subcomponent as if it were all part of the main project
2) CVSS judges a vulnerability globally, not based on deployment.
    - A service may have a high network vulnerability, but it may be deployed in a no-network environment.
    - A service may have a high vulnerability, but it may be deployed in a no-vulnerability environment.
    - CVSS Scores are not additive. You cannot combine them easily.