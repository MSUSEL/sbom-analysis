# Scayl

### Deployment Based Software Quality Assessment ###

_A tool for measuring the quality of software. This project uses CVSS scores, generated SBOM (Software Bill of
Materials) & Vulnerability reports to measure the security of a piece of software._

<div style="color: red;">Scayl only supports vulnerabilities with CVSS v3.1 scores. Because of the large number of 
vulnerability file formats that come along with modern programming languages, addressing every type of vulnerability was
not possible during the ten weeks in which this version of the tool was developed.
</div>

### Overview
#### [CLI](#cli)
#### [Building](#building)
#### [Usage](#usage)
#### [Context](#context)
#### [Results](#results)

**Documentation for the scayl library can be found [here](https://msusel.github.io/sbom-analysis/scayl/index.html)**

## CLI
```shell
Scayl 0.1.0

USAGE:
    scayl_bin.exe <SUBCOMMAND>

OPTIONS:
    -h, --help       Print help information
    -V, --version    Print version information

SUBCOMMANDS:
    analyze    Analyze a piece of software using various vulnerability formats.    
    en-mass    Analyze a directory of software using various vulnerability formats.
    help       Print this message or the help of the given subcommand(s)
```

### Building
The tool can be run using `cargo run -- ...arguments` or a native executable can be built using `cargo build`.<br>

#### Requirements
* Rust >=1.61.0
* Cargo >=0.36.0 (can be installed alongside rust at [rustup.rs](https://rustup.rs)
* [Grype (we used 0.38)](https://github.com/anchore/grype)
* [Syft (we used 0.46)](https://github.com/anchore/syft)
* [Trivy (we used 0.29.1)](https://github.com/aquasecurity/trivy)

Windows:
* WSL2 for the analyze.sh script to and analyze images
```shell
cargo build --release
cp target/release/scayl_bin.exe scayl.exe
```

Mac/Linux:
```shell
cargo build --release
cp target/release/scayl_bin ./scayl
```

### Usage
`scayl analyze --cyclonedx image/cyclonedx.json --context ./context/network.json --out image.json`

Analyzing multiple reports at once
`scayl en-mass --context ./context/web_api.json ./reports/`

## Context

This project utilizes deployment context, the context where the analyzed software is intended to be deployed.<br>
For more detail on the context model, see [Context.md](Context.md).<br>
The current context model consists of five elements:

* #### Network Configuration
  How the software is deployed on a network.
* #### Remote Access
  How accessible controls of the software are to remote users like admins.
* #### Information Sensitivity
  How sensitive the information utilized by a piece of software is.
* #### Command Line Permissions
  How the software is able to execute commands on the command line.
* #### File Permissions
  How the software is able to access the file system.

For more detail on the context model, see [Context.md](Context.md).

## Results

Producing & Understanding the Results of Scayl
Radar Chart

##### Producing

The file(s) used should be a CSV file with the headers: "id", "sum", "network", "files", "remote", "information", & "permissions". The default options for number of files is a single file or three to compare. From here you can select the CSV file(s) within the radar.R file. Read through all the code and follow the instructions commented to produce a radar bar chart. The lines that should be run differ depending on if you choose to compare three or not.

##### Understanding

Each file whether you make one or more will create a net-like shape on the pentagon base. There are 5 axis for the 5 categories. The net is created by plotting the mean score of each category on the corresponding axis. By plotting these 5 points, a net is created. The larger the net, the worse the file scores. It is on a scale from 0 to 1, where 0 is better than 1. Each label also contains the category score for you to analyze. Additionally, an overall score is computed to display. This chart makes it easier to compare files per category in addition to an overall score.
Stacked Bar Chart

##### Producing

The file used should be a CSV file with the headers: "id", "sum", "network", "files", "remote", "information", & "permissions". From here you can select the CSV within the stackedBar.R file. Read through all the code and follow the instructions commented to produce a default stacked bar chart. Customizing The dividing sections can be changed in Section 2. The title can be changed in Section 3. The color scheme can be changed inside of Section 3.

##### Understanding

For full view of the stacked bar chart, ensure that the image is expanded into full view. The stacked bar chart produced should result in a title containing the total amount of CVEs. The color code is graphed by severity. A darker color suggests a more severe effect. Each column graphs the total number of CVEs. The different categories show how the CVEs affect that category in particular. For example, one CVE might effect "Network Configuration" severly, but not "Command Line Permissions." So, "Network Configuration" will have an added count of the "High" category that would be shown in dark purple. "Command Line Permissions" would mark that CVE as low and count it for then pale purple category. In this way, you can see where the severity of CVE's line for a program.