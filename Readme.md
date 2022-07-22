# Scayl

### Deployment Based Software Quality Assessment ###

_A tool for measuring the quality of software. This project uses CVSS scores, generated SBOM (Software Bill of
Materials) & Vulnerability information to measure the security of a piece of software._

## Context

This project utilizes deployment context, the context where the analyzed software is intended to be deployed.
The current context model consists of five elements:

* ##### Network Configuration
  How the software is deployed on a network.
* ##### Remote Access
  How accessible controls of the software are to remote users like admins.
* ##### Information Sensitivity
  How sensitive the information utilized by a piece of software is.
* #### Command Line Permissions
  How the software is able to execute commands on the command line.
* ##### File Permissions
  How the software is able to access the file system.

For more detail on the context model, see [Context.md](Context.md).

## Building the Project
#### Requirements
* Rust >=1.61.0
* Cargo >=0.36.0 (can be installed alongside rust at [rustup.rs](https://rustup.rs)
* [Grype (we used 0.38)](https://github.com/anchore/grype)
* [Syft (we used 0.46)](https://github.com/anchore/syft)
* [Trivy (we used 0.29.1)](https://github.com/aquasecurity/trivy)

```shell
cargo build --release
cp target/release/scayl_bin.exe scayl.exe
```

##### Windows
* WSL2 for the analyze.sh script to and analyze images