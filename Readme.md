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