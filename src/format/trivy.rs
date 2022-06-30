use std::collections::BTreeMap;
use chrono::{DateTime, Utc};

// {
//     "OS": {
//       "Family": "ubuntu",
//       "Name": "20.04"
//     },
//     "ImageID": "sha256:282ef408c2af61448c9470f49d6a6134fb2afc59052008ef0f3d45a2727459e2",
//     "DiffIDs": [
//       "sha256:1fbfc8517de4c53055dc2fbcce0fd87b46e82a5e74c624cab2eb8d2bd5540479",
//       "sha256:443ba3640344669a410bbd0e054c17c9829d6786f50361c0a0018479b94290fe",
//       "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//       "sha256:677765a8040b195fc3790066d3384a7197c23e8637be94b104ae3c5908218682",
//       "sha256:f57470e745c8c3a2c627b04075608807c9fcc41dd4be977b752038c345ca0dfd",
//       "sha256:3d165ee6302dc3a39757c0db5aac4db6b0a31f6090c173bc74c74d119c57bd00",
//       "sha256:8e781ae4dd9d8b64783f91953dacdf7b79950839d6a43aa2669c403ba9a92bec",
//       "sha256:04f81f974caf68482158bafa755ff0d7af26da192ef14179796c6b00812e8a55",
//       "sha256:ca657a8da543f06107b3c82a4901b9d1f63a48df9bc74c8f9e3a5ecd893c7616",
//       "sha256:b58260f8eac45f04dd93aa9ce03f7a37a52798f8b3e74439d346433151103a43",
//       "sha256:0a6067c253bad28c8dd0dc29fd90c02b07e20d47a986dd74de4ebaaab7e26222",
//       "sha256:73bc1f58510cf84250b3fff47b26adb143fdb54dac8a694e7ef548586f75526f",
//       "sha256:3af693a198be859cfa19121d19f15d36d6b2bb57ceb35b05cd000404a8ecc087",
//       "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//       "sha256:b98ea571a301174863315ec9421df5b7f7751aeef11a78d3763f4f069e9ed5ef",
//       "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//       "sha256:9d45f0474323daf3fc73dec74ef8e829f6e2062498fd693dc81c2a33ee0874bd",
//       "sha256:17e448619c425c171cdc3fca18bc095786eb460fce0bc5441d008f3dd853741a",
//       "sha256:af4794b02aa578847073aef4d229db37ad8ba74da9d12910f8beffac6525e6ea",
//       "sha256:dfaaa719cddb40667882efafaa3e77db89300bddc108cac8731a4a75657cb574",
//       "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//       "sha256:63b764503f12264d318591dbbad36ee33c328e0cd8c34c23ca3b89970014e412",
//       "sha256:c9a8065bb7807f160fa026903736f7cb74a2d47cd209772bfb831df66a88bb6f",
//       "sha256:08c2267951ab1de49074b8a245d34537734adfb8ff7f7d872e180af7ac5e4a1c",
//       "sha256:7bca613b3dea92cdf30e63e4d9f96b84acdb866edbed9f6ee96cacd3d09dd227",
//       "sha256:2c3a9549ad001520cc3338aafc0dea550b4ed86fa4f1b2a15e7c7fed282a9d43",
//       "sha256:a7ddb6b14e6ad364c95eb168ff841753c4ad4f395d5fe3e4e9bee6540e4e7beb",
//       "sha256:15d937b4e8c6c2f56aab44e08e751d014ff41577937ebfaf508e2514d4fc5b34",
//       "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//       "sha256:7291efe3db43ecdb38d6ae2f1c65d8d8d08dbb0768810be23cf4c236399e66cf",
//       "sha256:24d22b92dd65b7896849913bd33a7f911135b793f8edd12ae7a922f4da98c8b9",
//       "sha256:99a38eecf20df4cb4918e910f75d8416f3038ef57847de7f1c6a66a53dfccfad",
//       "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//       "sha256:d9ba2b532b215dce77ad2b2edeeb6d3a6f624e36380cd9d2c09cb18df76d6dcf",
//       "sha256:33da158c825cb92d1a169fa6df994bbc3061e00f24f7f8960361ba970031cbdc",
//       "sha256:f2fe9b5d8c285a963c4711e747eff6226fa2b8212dd8186e1bfc52689d0ba495",
//       "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//       "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//       "sha256:e09d38c5e23b0c95167071ecc866c0e394e8df42d9327036394ff3ca69348279",
//       "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//       "sha256:3f4c8fbc0eb2c312d7abbb6dfad006ab74f6c37b5398e1cbd2d4ffa48f7f44fc",
//       "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//       "sha256:cac75d29784eedf8e41df6455a46769af5b6b5a27f6318a93fb03ec172240097",
//       "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//       "sha256:b2f38887caba172129c46e0aec3155247a4cefbda0d548ad0f502e42ee1f6f9c",
//       "sha256:b75e7327a83c4e3f090610e868c839bd2114858a843eb422b96406e42684e93f",
//       "sha256:eb63fb6137f8154920181d53c25d288d7e661bd0f0b50a1d4194d5adc43e827c",
//       "sha256:af6f084f9dc7659e930d74d100f4c9f2117834c9623cde927845a6754cb66f26",
//       "sha256:56a2da81609234cf2c4061f92cbdfa39692652f692ec585148b682477ab4abd4"
//     ],
//     "RepoTags": [
//       "molkars/pbd:1.0"
//     ],
//     "RepoDigests": [
//       "molkars/pbd@sha256:60c7882f5519d61716575a92b731ce38329845dc1bd18de5e601488415204094"
//     ],
//     "ImageConfig": {
//       "architecture": "amd64",
//       "created": "2022-06-08T16:20:54.3542114Z",
//       "history": [
//         {
//           "created": "2022-04-21T23:00:07Z",
//           "created_by": "/bin/sh -c #(nop) ADD file:064c61cc9ceed678689d2eaf3b3e61ec3bf5baf9288e5a7febcbab28c6adbfb6 in / "
//         },
//         {
//           "created": "2022-06-08T16:16:21Z",
//           "created_by": "WORKDIR /home",
//           "comment": "buildkit.dockerfile.v0",
//           "empty_layer": true
//         },
//         {
//           "created": "2022-06-08T16:16:22Z",
//           "created_by": "RUN /bin/sh -c git clone https://github.com/MSUSEL/msusel-pique.git # buildkit",
//           "comment": "buildkit.dockerfile.v0"
//         },
//         {
//           "created": "2022-06-08T16:16:23Z",
//           "created_by": "WORKDIR /home/msusel-pique",
//           "comment": "buildkit.dockerfile.v0",
//           "empty_layer": true
//         },
//         {
//           "created": "2022-06-08T16:19:06Z",
//           "created_by": "RUN /bin/sh -c mvn install -Dmaven.test.skip # buildkit",
//           "comment": "buildkit.dockerfile.v0"
//         },
//         {
//           "created": "2022-06-08T16:19:06Z",
//           "created_by": "WORKDIR /home",
//           "comment": "buildkit.dockerfile.v0",
//           "empty_layer": true
//         },
//         {
//           "created": "2022-06-08T16:19:08Z",
//           "created_by": "RUN /bin/sh -c git clone https://github.com/MSUSEL/msusel-pique-bin-docker # buildkit",
//           "comment": "buildkit.dockerfile.v0"
//         },
//         {
//           "created": "2022-06-08T16:19:08Z",
//           "created_by": "WORKDIR /home/msusel-pique-bin-docker",
//           "comment": "buildkit.dockerfile.v0",
//           "empty_layer": true
//         },
//         {
//           "created": "2022-06-08T16:20:52Z",
//           "created_by": "RUN /bin/sh -c mvn package -Dmaven.test.skip # buildkit",
//           "comment": "buildkit.dockerfile.v0"
//         },
//         {
//           "created": "2022-06-08T16:20:52Z",
//           "created_by": "RUN /bin/sh -c mkdir \"/input\" # buildkit",
//           "comment": "buildkit.dockerfile.v0",
//           "empty_layer": true
//         },
//         {
//           "created": "2022-06-08T16:20:52Z",
//           "created_by": "VOLUME [/input]",
//           "comment": "buildkit.dockerfile.v0",
//           "empty_layer": true
//         },
//         {
//           "created": "2022-06-08T16:20:53Z",
//           "created_by": "RUN /bin/sh -c mkdir \"/output\" # buildkit",
//           "comment": "buildkit.dockerfile.v0",
//           "empty_layer": true
//         },
//         {
//           "created": "2022-06-08T16:20:53Z",
//           "created_by": "VOLUME [/output]",
//           "comment": "buildkit.dockerfile.v0",
//           "empty_layer": true
//         },
//         {
//           "created": "2022-06-08T16:20:53Z",
//           "created_by": "RUN /bin/sh -c chmod -R +x /input # buildkit",
//           "comment": "buildkit.dockerfile.v0",
//           "empty_layer": true
//         },
//         {
//           "created": "2022-06-08T16:20:54Z",
//           "created_by": "RUN /bin/sh -c chmod -R +x /output # buildkit",
//           "comment": "buildkit.dockerfile.v0",
//           "empty_layer": true
//         },
//         {
//           "created": "2022-06-08T16:20:54Z",
//           "created_by": "ENTRYPOINT [\"java\" \"-jar\" \"/home/msusel-pique-bin-docker/target/msusel-pique-bin-0.0.1-jar-with-dependencies.jar\"]",
//           "comment": "buildkit.dockerfile.v0",
//           "empty_layer": true
//         }
//       ],
//       "os": "linux",
//       "rootfs": {
//         "type": "layers",
//         "diff_ids": [
//           "sha256:1fbfc8517de4c53055dc2fbcce0fd87b46e82a5e74c624cab2eb8d2bd5540479",
//           "sha256:443ba3640344669a410bbd0e054c17c9829d6786f50361c0a0018479b94290fe",
//           "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//           "sha256:677765a8040b195fc3790066d3384a7197c23e8637be94b104ae3c5908218682",
//           "sha256:f57470e745c8c3a2c627b04075608807c9fcc41dd4be977b752038c345ca0dfd",
//           "sha256:3d165ee6302dc3a39757c0db5aac4db6b0a31f6090c173bc74c74d119c57bd00",
//           "sha256:8e781ae4dd9d8b64783f91953dacdf7b79950839d6a43aa2669c403ba9a92bec",
//           "sha256:04f81f974caf68482158bafa755ff0d7af26da192ef14179796c6b00812e8a55",
//           "sha256:ca657a8da543f06107b3c82a4901b9d1f63a48df9bc74c8f9e3a5ecd893c7616",
//           "sha256:b58260f8eac45f04dd93aa9ce03f7a37a52798f8b3e74439d346433151103a43",
//           "sha256:0a6067c253bad28c8dd0dc29fd90c02b07e20d47a986dd74de4ebaaab7e26222",
//           "sha256:73bc1f58510cf84250b3fff47b26adb143fdb54dac8a694e7ef548586f75526f",
//           "sha256:3af693a198be859cfa19121d19f15d36d6b2bb57ceb35b05cd000404a8ecc087",
//           "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//           "sha256:b98ea571a301174863315ec9421df5b7f7751aeef11a78d3763f4f069e9ed5ef",
//           "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//           "sha256:9d45f0474323daf3fc73dec74ef8e829f6e2062498fd693dc81c2a33ee0874bd",
//           "sha256:17e448619c425c171cdc3fca18bc095786eb460fce0bc5441d008f3dd853741a",
//           "sha256:af4794b02aa578847073aef4d229db37ad8ba74da9d12910f8beffac6525e6ea",
//           "sha256:dfaaa719cddb40667882efafaa3e77db89300bddc108cac8731a4a75657cb574",
//           "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//           "sha256:63b764503f12264d318591dbbad36ee33c328e0cd8c34c23ca3b89970014e412",
//           "sha256:c9a8065bb7807f160fa026903736f7cb74a2d47cd209772bfb831df66a88bb6f",
//           "sha256:08c2267951ab1de49074b8a245d34537734adfb8ff7f7d872e180af7ac5e4a1c",
//           "sha256:7bca613b3dea92cdf30e63e4d9f96b84acdb866edbed9f6ee96cacd3d09dd227",
//           "sha256:2c3a9549ad001520cc3338aafc0dea550b4ed86fa4f1b2a15e7c7fed282a9d43",
//           "sha256:a7ddb6b14e6ad364c95eb168ff841753c4ad4f395d5fe3e4e9bee6540e4e7beb",
//           "sha256:15d937b4e8c6c2f56aab44e08e751d014ff41577937ebfaf508e2514d4fc5b34",
//           "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//           "sha256:7291efe3db43ecdb38d6ae2f1c65d8d8d08dbb0768810be23cf4c236399e66cf",
//           "sha256:24d22b92dd65b7896849913bd33a7f911135b793f8edd12ae7a922f4da98c8b9",
//           "sha256:99a38eecf20df4cb4918e910f75d8416f3038ef57847de7f1c6a66a53dfccfad",
//           "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//           "sha256:d9ba2b532b215dce77ad2b2edeeb6d3a6f624e36380cd9d2c09cb18df76d6dcf",
//           "sha256:33da158c825cb92d1a169fa6df994bbc3061e00f24f7f8960361ba970031cbdc",
//           "sha256:f2fe9b5d8c285a963c4711e747eff6226fa2b8212dd8186e1bfc52689d0ba495",
//           "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//           "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//           "sha256:e09d38c5e23b0c95167071ecc866c0e394e8df42d9327036394ff3ca69348279",
//           "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//           "sha256:3f4c8fbc0eb2c312d7abbb6dfad006ab74f6c37b5398e1cbd2d4ffa48f7f44fc",
//           "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//           "sha256:cac75d29784eedf8e41df6455a46769af5b6b5a27f6318a93fb03ec172240097",
//           "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
//           "sha256:b2f38887caba172129c46e0aec3155247a4cefbda0d548ad0f502e42ee1f6f9c",
//           "sha256:b75e7327a83c4e3f090610e868c839bd2114858a843eb422b96406e42684e93f",
//           "sha256:eb63fb6137f8154920181d53c25d288d7e661bd0f0b50a1d4194d5adc43e827c",
//           "sha256:af6f084f9dc7659e930d74d100f4c9f2117834c9623cde927845a6754cb66f26",
//           "sha256:56a2da81609234cf2c4061f92cbdfa39692652f692ec585148b682477ab4abd4"
//         ]
//       },
//       "config": {
//         "Entrypoint": [
//           "java",
//           "-jar",
//           "/home/msusel-pique-bin-docker/target/msusel-pique-bin-0.0.1-jar-with-dependencies.jar"
//         ],
//         "Env": [
//           "PATH=/root/.cargo/bin:/opt/apache-maven-3.8.5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
//           "DEBIAN_FRONTEND=noninteractive",
//           "TZ=Etc/UTC",
//           "RUST_VERSION=1.60.0"
//         ],
//         "Volumes": {
//           "/input": {},
//           "/output": {}
//         },
//         "WorkingDir": "/home/msusel-pique-bin-docker"
//       }
//     }
//   },

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TrivyMetadata {
    #[serde(rename = "OS")]
    pub os: String,
    #[serde(rename = "ImageID")]
    pub image_id: String,
    #[serde(rename = "DiffIDs")]
    pub diff_ids: Vec<String>,
    pub repo_tags: Vec<String>,
    pub repo_digests: Vec<String>,
    pub image_config: ImageConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImageConfig {
    pub architecture: String,
    pub created: String,
    pub history: Vec<History>,
    pub os: String,
    pub rootfs: RootFS,
    pub config: Config,
}

fn default_bool() -> bool {
    false
}

#[derive(Debug, Serialize, Deserialize)]
pub struct History {
    pub created: String,
    pub created_by: String,
    pub comment: Option<String>,
    #[serde(default = "default_bool")]
    pub empty_layer: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RootFS {
    pub r#type: String,
    pub diff_ids: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TrivyJson {
    pub schema_version: u32,
    pub artifact_name: String,
    pub artifact_type: String,
    pub metadata: TrivyMetadata,
    pub results: Vec<TrivyResult>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TrivyResult {
    pub target: String,
    pub class: String,
    pub r#type: String,
    pub vulnerabilities: Vec<TrivyVulnerability>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TrivyVulnerability {
    #[serde(rename = "VulnerabilityID")]
    pub vulnerability_id: String,
    pub pkg_name: String,
    pub installed_version: String,
    pub fixed_version: String,
    pub layer: TrivyLayer,
    pub severity_source: String,
    #[serde(rename = "PrimaryURL")]
    pub primary_url: String,
    pub data_source: TrivyDataSource,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub cwe_ids: Vec<String>,
    #[serde(rename = "CVSS")]
    pub cvss: TrivyCvss,
    pub references: Vec<String>,
    pub published_date: DateTime<Utc>,
    pub last_modified_date: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TrivyLayer {
    pub diff_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TrivyDataSource {
    #[serde(rename = "ID")]
    pub id: String,
    pub name: String,
    #[serde(rename = "URL")]
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TrivyCvss {
    pub nvd: TrivyNvd,
    pub redhat: TrivyRedhat,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TrivyNvd {
    pub v2_vector: String,
    pub v3_vector: String,
    pub v2_score: f64,
    pub v3_score: f64,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TrivyRedhat {
    pub v3_vector: String,
    pub v3_score: f64,
}


#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    pub entrypoint: Vec<String>,
    pub env: Vec<String>,
    pub volumes: BTreeMap<String, String>,
    pub working_dir: String,
}