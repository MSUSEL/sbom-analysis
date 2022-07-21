use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;
use serde_json::Value;

impl Sarif {
    pub fn cleanse(&mut self) {
        self.runs
            .iter_mut()
            .filter_map(|v| v.results.as_mut())
            .flat_map(|v| v.iter_mut())
            .filter_map(|v| v.rule_id.as_mut())
            .filter(|v| v.starts_with("CVE"))
            .for_each(|v| {
                let split = v.split("-").collect::<Vec<_>>();
                if split.len() > 3 {
                    *v = String::from(split[0..3].join("-"))
                }
            });
    }

    pub fn cvss_scores<T: FromIterator<f64>>(&self) -> T {
        self.runs
            .iter()
            .filter_map(|run| run.tool.driver.rules.as_ref())
            .flat_map(|rules| rules.iter())
            .filter_map(|rule| rule.properties.as_ref())
            .filter_map(|props| props.get("security-severity"))
            .filter_map(|v| v.as_str())
            .filter_map(|v| f64::from_str(v).ok())
            .collect::<T>()
    }

    pub fn cve_ids<'a, T: FromIterator<&'a String>>(&'a self) -> T {
        self.runs
            .iter()
            .filter_map(|run| run.results.as_ref())
            .flat_map(|results| results.iter())
            .filter_map(|v| v.rule_id.as_ref())
            .collect::<T>()
    }

    pub fn average_cvss_score(&self) -> f64 {
        let scores = self.cvss_scores::<Vec<_>>();
        scores.iter().sum::<f64>() / scores.len() as f64
    }

    pub fn median_cvss_score(&self) -> f64 {
        let mut scores = self.cvss_scores::<Vec<_>>();
        scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
        let mid = scores.len() / 2;
        if scores.len() % 2 == 0 {
            scores[mid]
        } else {
            scores[mid..=mid + 1].iter().sum::<f64>() / 2.0
        }
    }

    pub fn diff_cvss<T: FromIterator<String>>(&self, other: &Self) -> T {
        let this = self.cve_ids::<BTreeSet<_>>();
        let other = other.cve_ids::<BTreeSet<_>>();
        this.difference(&other).cloned().cloned().collect::<T>()
    }
}

/// Static Analysis Results Format (SARIF) Version 2.1.0 JSON Schema: a standard format for
/// the output of static analysis tools.
#[derive(Debug, Serialize, Deserialize)]
pub struct Sarif {
    /// The URI of the JSON schema corresponding to the version.
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    /// References to external property files that share data between runs.
    #[serde(rename = "inlineExternalProperties")]
    pub inline_external_properties: Option<Vec<ExternalProperties>>,
    /// Key/value pairs that provide additional information about the log file.
    pub properties: Option<PropertyBag>,
    /// The set of runs contained in this log file.
    pub runs: Vec<Run>,
    /// The SARIF format version of this log file.
    pub version: Version,
}

/// The top-level element of an external property file.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalProperties {
    /// Addresses that will be merged with a separate run.
    pub addresses: Option<Vec<Address>>,
    /// An array of artifact objects that will be merged with a separate run.
    pub artifacts: Option<Vec<Artifact>>,
    /// A conversion object that will be merged with a separate run.
    pub conversion: Option<Conversion>,
    /// The analysis tool object that will be merged with a separate run.
    pub driver: Option<ToolComponent>,
    /// Tool extensions that will be merged with a separate run.
    pub extensions: Option<Vec<ToolComponent>>,
    /// Key/value pairs that provide additional information that will be merged with a separate
    /// run.
    #[serde(rename = "externalizedProperties")]
    pub externalized_properties: Option<PropertyBag>,
    /// An array of graph objects that will be merged with a separate run.
    pub graphs: Option<Vec<Graph>>,
    /// A stable, unique identifer for this external properties object, in the form of a GUID.
    pub guid: Option<String>,
    /// Describes the invocation of the analysis tool that will be merged with a separate run.
    pub invocations: Option<Vec<Invocation>>,
    /// An array of logical locations such as namespaces, types or functions that will be merged
    /// with a separate run.
    #[serde(rename = "logicalLocations")]
    pub logical_locations: Option<Vec<LogicalLocation>>,
    /// Tool policies that will be merged with a separate run.
    pub policies: Option<Vec<ToolComponent>>,
    /// Key/value pairs that provide additional information about the external properties.
    pub properties: Option<PropertyBag>,
    /// An array of result objects that will be merged with a separate run.
    pub results: Option<Vec<TrivyResult>>,
    /// A stable, unique identifer for the run associated with this external properties object,
    /// in the form of a GUID.
    #[serde(rename = "runGuid")]
    pub run_guid: Option<String>,
    /// The URI of the JSON schema corresponding to the version of the external property file
    /// format.
    pub schema: Option<String>,
    /// Tool taxonomies that will be merged with a separate run.
    pub taxonomies: Option<Vec<ToolComponent>>,
    /// An array of threadFlowLocation objects that will be merged with a separate run.
    #[serde(rename = "threadFlowLocations")]
    pub thread_flow_locations: Option<Vec<ThreadFlowLocation>>,
    /// Tool translations that will be merged with a separate run.
    pub translations: Option<Vec<ToolComponent>>,
    /// The SARIF format version of this external properties object.
    pub version: Option<Version>,
    /// Requests that will be merged with a separate run.
    #[serde(rename = "webRequests")]
    pub web_requests: Option<Vec<WebRequest>>,
    /// Responses that will be merged with a separate run.
    #[serde(rename = "webResponses")]
    pub web_responses: Option<Vec<WebResponse>>,
}

/// A physical or virtual address, or a range of addresses, in an 'addressable region'
/// (memory or a binary file).
///
/// The address of the location.
#[derive(Debug, Serialize, Deserialize)]
pub struct Address {
    /// The address expressed as a byte offset from the start of the addressable region.
    #[serde(rename = "absoluteAddress")]
    pub absolute_address: Option<i64>,
    /// A human-readable fully qualified name that is associated with the address.
    #[serde(rename = "fullyQualifiedName")]
    pub fully_qualified_name: Option<String>,
    /// The index within run.addresses of the cached object for this address.
    pub index: Option<i64>,
    /// An open-ended string that identifies the address kind. 'data', 'function',
    /// 'header','instruction', 'module', 'page', 'section', 'segment', 'stack', 'stackFrame',
    /// 'table' are well-known values.
    pub kind: Option<String>,
    /// The number of bytes in this range of addresses.
    pub length: Option<i64>,
    /// A name that is associated with the address, e.g., '.text'.
    pub name: Option<String>,
    /// The byte offset of this address from the absolute or relative address of the parent
    /// object.
    #[serde(rename = "offsetFromParent")]
    pub offset_from_parent: Option<i64>,
    /// The index within run.addresses of the parent object.
    #[serde(rename = "parentIndex")]
    pub parent_index: Option<i64>,
    /// Key/value pairs that provide additional information about the address.
    pub properties: Option<PropertyBag>,
    /// The address expressed as a byte offset from the absolute address of the top-most parent
    /// object.
    #[serde(rename = "relativeAddress")]
    pub relative_address: Option<i64>,
}

/// Key/value pairs that provide additional information about the address.
///
/// Key/value pairs that provide additional information about the object.
///
/// Key/value pairs that provide additional information about the artifact content.
///
/// Key/value pairs that provide additional information about the message.
///
/// Key/value pairs that provide additional information about the artifact location.
///
/// Key/value pairs that provide additional information about the artifact.
///
/// Contains configuration information specific to a report.
///
/// Key/value pairs that provide additional information about the reporting configuration.
///
/// Key/value pairs that provide additional information about the reporting descriptor
/// reference.
///
/// Key/value pairs that provide additional information about the toolComponentReference.
///
/// Key/value pairs that provide additional information about the configuration override.
///
/// Key/value pairs that provide additional information about the invocation.
///
/// Key/value pairs that provide additional information about the exception.
///
/// Key/value pairs that provide additional information about the region.
///
/// Key/value pairs that provide additional information about the logical location.
///
/// Key/value pairs that provide additional information about the physical location.
///
/// Key/value pairs that provide additional information about the location.
///
/// Key/value pairs that provide additional information about the location relationship.
///
/// Key/value pairs that provide additional information about the stack frame.
///
/// Key/value pairs that provide additional information about the stack.
///
/// Key/value pairs that provide additional information about the notification.
///
/// Key/value pairs that provide additional information about the conversion.
///
/// Key/value pairs that provide additional information about the report.
///
/// Key/value pairs that provide additional information about the tool component.
///
/// Key/value pairs that provide additional information about the translation metadata.
///
/// Key/value pairs that provide additional information about the tool.
///
/// Key/value pairs that provide additional information that will be merged with a separate
/// run.
///
/// Key/value pairs that provide additional information about the edge.
///
/// Key/value pairs that provide additional information about the node.
///
/// Key/value pairs that provide additional information about the graph.
///
/// Key/value pairs that provide additional information about the external properties.
///
/// Key/value pairs that provide additional information about the attachment.
///
/// Key/value pairs that provide additional information about the rectangle.
///
/// Key/value pairs that provide additional information about the code flow.
///
/// Key/value pairs that provide additional information about the threadflow location.
///
/// Key/value pairs that provide additional information about the request.
///
/// Key/value pairs that provide additional information about the response.
///
/// Key/value pairs that provide additional information about the thread flow.
///
/// Key/value pairs that provide additional information about the change.
///
/// Key/value pairs that provide additional information about the replacement.
///
/// Key/value pairs that provide additional information about the fix.
///
/// Key/value pairs that provide additional information about the edge traversal.
///
/// Key/value pairs that provide additional information about the graph traversal.
///
/// Key/value pairs that provide additional information about the result.
///
/// Key/value pairs that provide additional information about the suppression.
///
/// Key/value pairs that provide additional information about the log file.
///
/// Key/value pairs that provide additional information about the run automation details.
///
/// Key/value pairs that provide additional information about the external property file.
///
/// Key/value pairs that provide additional information about the external property files.
///
/// Key/value pairs that provide additional information about the run.
///
/// Key/value pairs that provide additional information about the special locations.
///
/// Key/value pairs that provide additional information about the version control details.
// #[derive(Debug, Serialize, Deserialize)]
pub type PropertyBag = BTreeMap<String, Value>;

/// A single artifact. In some cases, this artifact might be nested within another artifact.
#[derive(Debug, Serialize, Deserialize)]
pub struct Artifact {
    /// The contents of the artifact.
    pub contents: Option<ArtifactContent>,
    /// A short description of the artifact.
    pub description: Option<Message>,
    /// Specifies the encoding for an artifact object that refers to a text file.
    pub encoding: Option<String>,
    /// A dictionary, each of whose keys is the name of a hash function and each of whose values
    /// is the hashed value of the artifact produced by the specified hash function.
    pub hashes: Option<HashMap<String, String>>,
    /// The Coordinated Universal Time (UTC) date and time at which the artifact was most
    /// recently modified. See "Date/time properties" in the SARIF spec for the required format.
    #[serde(rename = "lastModifiedTimeUtc")]
    pub last_modified_time_utc: Option<String>,
    /// The length of the artifact in bytes.
    pub length: Option<i64>,
    /// The location of the artifact.
    pub location: Option<ArtifactLocation>,
    /// The MIME type (RFC 2045) of the artifact.
    #[serde(rename = "mimeType")]
    pub mime_type: Option<String>,
    /// The offset in bytes of the artifact within its containing artifact.
    pub offset: Option<i64>,
    /// Identifies the index of the immediate parent of the artifact, if this artifact is nested.
    #[serde(rename = "parentIndex")]
    pub parent_index: Option<i64>,
    /// Key/value pairs that provide additional information about the artifact.
    pub properties: Option<PropertyBag>,
    /// The role or roles played by the artifact in the analysis.
    pub roles: Option<Vec<Role>>,
    /// Specifies the source language for any artifact object that refers to a text file that
    /// contains source code.
    #[serde(rename = "sourceLanguage")]
    pub source_language: Option<String>,
}

/// The contents of the artifact.
///
/// Represents the contents of an artifact.
///
/// The portion of the artifact contents within the specified region.
///
/// The body of the request.
///
/// The body of the response.
///
/// The content to insert at the location specified by the 'deletedRegion' property.
#[derive(Debug, Serialize, Deserialize)]
pub struct ArtifactContent {
    /// MIME Base64-encoded content from a binary artifact, or from a text artifact in its
    /// original encoding.
    pub binary: Option<String>,
    /// Key/value pairs that provide additional information about the artifact content.
    pub properties: Option<PropertyBag>,
    /// An alternate rendered representation of the artifact (e.g., a decompiled representation
    /// of a binary region).
    pub rendered: Option<MultiformatMessageString>,
    /// UTF-8-encoded content from a text artifact.
    pub text: Option<String>,
}

/// An alternate rendered representation of the artifact (e.g., a decompiled representation
/// of a binary region).
///
/// A message string or message format string rendered in multiple formats.
///
/// A comprehensive description of the tool component.
///
/// A description of the report. Should, as far as possible, provide details sufficient to
/// enable resolution of any problem indicated by the result.
///
/// Provides the primary documentation for the report, useful when there is no online
/// documentation.
///
/// A concise description of the report. Should be a single sentence that is understandable
/// when visible space is limited to a single line of text.
///
/// A brief description of the tool component.
///
/// A comprehensive description of the translation metadata.
///
/// A brief description of the translation metadata.
#[derive(Debug, Serialize, Deserialize)]
pub struct MultiformatMessageString {
    /// A Markdown message string or format string.
    pub markdown: Option<String>,
    /// Key/value pairs that provide additional information about the message.
    pub properties: Option<PropertyBag>,
    /// A plain text message string or format string.
    pub text: String,
}

/// A short description of the artifact.
///
/// A short description of the artifact location.
///
/// A message relevant to the region.
///
/// A message relevant to the location.
///
/// A description of the location relationship.
///
/// A message relevant to this call stack.
///
/// A message that describes the condition that was encountered.
///
/// A description of the reporting descriptor relationship.
///
/// A description of the graph.
///
/// A short description of the edge.
///
/// A short description of the node.
///
/// A message describing the role played by the attachment.
///
/// A message relevant to the rectangle.
///
/// A message relevant to the code flow.
///
/// A message relevant to the thread flow.
///
/// A message that describes the proposed fix, enabling viewers to present the proposed
/// change to an end user.
///
/// A description of this graph traversal.
///
/// A message to display to the user as the edge is traversed.
///
/// A message that describes the result. The first sentence of the message only will be
/// displayed when visible space is limited.
///
/// A description of the identity and role played within the engineering system by this
/// object's containing run object.
///
/// Encapsulates a message intended to be read by the end user.
#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    /// An array of strings to substitute into the message string.
    pub arguments: Option<Vec<String>>,
    /// The identifier for this message.
    pub id: Option<String>,
    /// A Markdown message string.
    pub markdown: Option<String>,
    /// Key/value pairs that provide additional information about the message.
    pub properties: Option<PropertyBag>,
    /// A plain text message string.
    pub text: Option<String>,
}

/// The location of the artifact.
///
/// Specifies the location of an artifact.
///
/// An absolute URI specifying the location of the analysis tool's executable.
///
/// A file containing the standard error stream from the process that was invoked.
///
/// A file containing the standard input stream to the process that was invoked.
///
/// A file containing the standard output stream from the process that was invoked.
///
/// A file containing the interleaved standard output and standard error stream from the
/// process that was invoked.
///
/// The working directory for the analysis tool run.
///
/// Identifies the artifact that the analysis tool was instructed to scan. This need not be
/// the same as the artifact where the result actually occurred.
///
/// The location of the attachment.
///
/// The location of the artifact to change.
///
/// The location of the external property file.
///
/// Provides a suggestion to SARIF consumers to display file paths relative to the specified
/// location.
///
/// The location in the local file system to which the root of the repository was mapped at
/// the time of the analysis.
#[derive(Debug, Serialize, Deserialize)]
pub struct ArtifactLocation {
    /// A short description of the artifact location.
    pub description: Option<Message>,
    /// The index within the run artifacts array of the artifact object associated with the
    /// artifact location.
    pub index: Option<i64>,
    /// Key/value pairs that provide additional information about the artifact location.
    pub properties: Option<PropertyBag>,
    /// A string containing a valid relative or absolute URI.
    pub uri: Option<String>,
    /// A string which indirectly specifies the absolute URI with respect to which a relative URI
    /// in the "uri" property is interpreted.
    #[serde(rename = "uriBaseId")]
    pub uri_base_id: Option<String>,
}

/// A conversion object that will be merged with a separate run.
///
/// Describes how a converter transformed the output of a static analysis tool from the
/// analysis tool's native output format into the SARIF format.
///
/// A conversion object that describes how a converter transformed an analysis tool's native
/// reporting format into the SARIF format.
#[derive(Debug, Serialize, Deserialize)]
pub struct Conversion {
    /// The locations of the analysis tool's per-run log files.
    #[serde(rename = "analysisToolLogFiles")]
    pub analysis_tool_log_files: Option<Vec<ArtifactLocation>>,
    /// An invocation object that describes the invocation of the converter.
    pub invocation: Option<Invocation>,
    /// Key/value pairs that provide additional information about the conversion.
    pub properties: Option<PropertyBag>,
    /// A tool object that describes the converter.
    pub tool: Tool,
}

/// An invocation object that describes the invocation of the converter.
///
/// The runtime environment of the analysis tool run.
#[derive(Debug, Serialize, Deserialize)]
pub struct Invocation {
    /// The account that ran the analysis tool.
    pub account: Option<String>,
    /// An array of strings, containing in order the command line arguments passed to the tool
    /// from the operating system.
    pub arguments: Option<Vec<String>>,
    /// The command line used to invoke the tool.
    #[serde(rename = "commandLine")]
    pub command_line: Option<String>,
    /// The Coordinated Universal Time (UTC) date and time at which the run ended. See "Date/time
    /// properties" in the SARIF spec for the required format.
    #[serde(rename = "endTimeUtc")]
    pub end_time_utc: Option<String>,
    /// The environment variables associated with the analysis tool process, expressed as
    /// key/value pairs.
    #[serde(rename = "environmentVariables")]
    pub environment_variables: Option<HashMap<String, String>>,
    /// An absolute URI specifying the location of the analysis tool's executable.
    #[serde(rename = "executableLocation")]
    pub executable_location: Option<ArtifactLocation>,
    /// Specifies whether the tool's execution completed successfully.
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,
    /// The process exit code.
    #[serde(rename = "exitCode")]
    pub exit_code: Option<i64>,
    /// The reason for the process exit.
    #[serde(rename = "exitCodeDescription")]
    pub exit_code_description: Option<String>,
    /// The name of the signal that caused the process to exit.
    #[serde(rename = "exitSignalName")]
    pub exit_signal_name: Option<String>,
    /// The numeric value of the signal that caused the process to exit.
    #[serde(rename = "exitSignalNumber")]
    pub exit_signal_number: Option<i64>,
    /// The machine that hosted the analysis tool run.
    pub machine: Option<String>,
    /// An array of configurationOverride objects that describe notifications related runtime
    /// overrides.
    #[serde(rename = "notificationConfigurationOverrides")]
    pub notification_configuration_overrides: Option<Vec<ConfigurationOverride>>,
    /// The process id for the analysis tool run.
    #[serde(rename = "processId")]
    pub process_id: Option<i64>,
    /// The reason given by the operating system that the process failed to start.
    #[serde(rename = "processStartFailureMessage")]
    pub process_start_failure_message: Option<String>,
    /// Key/value pairs that provide additional information about the invocation.
    pub properties: Option<PropertyBag>,
    /// The locations of any response files specified on the tool's command line.
    #[serde(rename = "responseFiles")]
    pub response_files: Option<Vec<ArtifactLocation>>,
    /// An array of configurationOverride objects that describe rules related runtime overrides.
    #[serde(rename = "ruleConfigurationOverrides")]
    pub rule_configuration_overrides: Option<Vec<ConfigurationOverride>>,
    /// The Coordinated Universal Time (UTC) date and time at which the run started. See
    /// "Date/time properties" in the SARIF spec for the required format.
    #[serde(rename = "startTimeUtc")]
    pub start_time_utc: Option<String>,
    /// A file containing the standard error stream from the process that was invoked.
    pub stderr: Option<ArtifactLocation>,
    /// A file containing the standard input stream to the process that was invoked.
    pub stdin: Option<ArtifactLocation>,
    /// A file containing the standard output stream from the process that was invoked.
    pub stdout: Option<ArtifactLocation>,
    /// A file containing the interleaved standard output and standard error stream from the
    /// process that was invoked.
    #[serde(rename = "stdoutStderr")]
    pub stdout_stderr: Option<ArtifactLocation>,
    /// A list of conditions detected by the tool that are relevant to the tool's configuration.
    #[serde(rename = "toolConfigurationNotifications")]
    pub tool_configuration_notifications: Option<Vec<Notification>>,
    /// A list of runtime conditions detected by the tool during the analysis.
    #[serde(rename = "toolExecutionNotifications")]
    pub tool_execution_notifications: Option<Vec<Notification>>,
    /// The working directory for the analysis tool run.
    #[serde(rename = "workingDirectory")]
    pub working_directory: Option<ArtifactLocation>,
}

/// Information about how a specific rule or notification was reconfigured at runtime.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigurationOverride {
    /// Specifies how the rule or notification was configured during the scan.
    pub configuration: ReportingConfiguration,
    /// A reference used to locate the descriptor whose configuration was overridden.
    pub descriptor: ReportingDescriptorReference,
    /// Key/value pairs that provide additional information about the configuration override.
    pub properties: Option<PropertyBag>,
}

/// Specifies how the rule or notification was configured during the scan.
///
/// Information about a rule or notification that can be configured at runtime.
///
/// Default reporting configuration information.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReportingConfiguration {
    /// Specifies whether the report may be produced during the scan.
    pub enabled: Option<bool>,
    /// Specifies the failure level for the report.
    pub level: Option<Level>,
    /// Contains configuration information specific to a report.
    pub parameters: Option<PropertyBag>,
    /// Key/value pairs that provide additional information about the reporting configuration.
    pub properties: Option<PropertyBag>,
    /// Specifies the relative priority of the report. Used for analysis output only.
    pub rank: Option<f64>,
}

/// A reference used to locate the descriptor whose configuration was overridden.
///
/// A reference used to locate the rule descriptor associated with this notification.
///
/// A reference used to locate the descriptor relevant to this notification.
///
/// A reference to the related reporting descriptor.
///
/// A reference used to locate the rule descriptor relevant to this result.
///
/// Information about how to locate a relevant reporting descriptor.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReportingDescriptorReference {
    /// A guid that uniquely identifies the descriptor.
    pub guid: Option<String>,
    /// The id of the descriptor.
    pub id: Option<String>,
    /// The index into an array of descriptors in toolComponent.ruleDescriptors,
    /// toolComponent.notificationDescriptors, or toolComponent.taxonomyDescriptors, depending on
    /// context.
    pub index: Option<i64>,
    /// Key/value pairs that provide additional information about the reporting descriptor
    /// reference.
    pub properties: Option<PropertyBag>,
    /// A reference used to locate the toolComponent associated with the descriptor.
    #[serde(rename = "toolComponent")]
    pub tool_component: Option<ToolComponentReference>,
}

/// A reference used to locate the toolComponent associated with the descriptor.
///
/// Identifies a particular toolComponent object, either the driver or an extension.
///
/// The component which is strongly associated with this component. For a translation, this
/// refers to the component which has been translated. For an extension, this is the driver
/// that provides the extension's plugin model.
#[derive(Debug, Serialize, Deserialize)]
pub struct ToolComponentReference {
    /// The 'guid' property of the referenced toolComponent.
    pub guid: Option<String>,
    /// An index into the referenced toolComponent in tool.extensions.
    pub index: Option<i64>,
    /// The 'name' property of the referenced toolComponent.
    pub name: Option<String>,
    /// Key/value pairs that provide additional information about the toolComponentReference.
    pub properties: Option<PropertyBag>,
}

/// Describes a condition relevant to the tool itself, as opposed to being relevant to a
/// target being analyzed by the tool.
#[derive(Debug, Serialize, Deserialize)]
pub struct Notification {
    /// A reference used to locate the rule descriptor associated with this notification.
    #[serde(rename = "associatedRule")]
    pub associated_rule: Option<ReportingDescriptorReference>,
    /// A reference used to locate the descriptor relevant to this notification.
    pub descriptor: Option<ReportingDescriptorReference>,
    /// The runtime exception, if any, relevant to this notification.
    pub exception: Option<Exception>,
    /// A value specifying the severity level of the notification.
    pub level: Option<Level>,
    /// The locations relevant to this notification.
    pub locations: Option<Vec<Location>>,
    /// A message that describes the condition that was encountered.
    pub message: Message,
    /// Key/value pairs that provide additional information about the notification.
    pub properties: Option<PropertyBag>,
    /// The thread identifier of the code that generated the notification.
    #[serde(rename = "threadId")]
    pub thread_id: Option<i64>,
    /// The Coordinated Universal Time (UTC) date and time at which the analysis tool generated
    /// the notification.
    #[serde(rename = "timeUtc")]
    pub time_utc: Option<String>,
}

/// The runtime exception, if any, relevant to this notification.
///
/// Describes a runtime exception encountered during the execution of an analysis tool.
#[derive(Debug, Serialize, Deserialize)]
pub struct Exception {
    /// An array of exception objects each of which is considered a cause of this exception.
    #[serde(rename = "innerExceptions")]
    pub inner_exceptions: Option<Vec<Exception>>,
    /// A string that identifies the kind of exception, for example, the fully qualified type
    /// name of an object that was thrown, or the symbolic name of a signal.
    pub kind: Option<String>,
    /// A message that describes the exception.
    pub message: Option<String>,
    /// Key/value pairs that provide additional information about the exception.
    pub properties: Option<PropertyBag>,
    /// The sequence of function calls leading to the exception.
    pub stack: Option<Stack>,
}

/// The sequence of function calls leading to the exception.
///
/// A call stack that is relevant to a result.
///
/// The call stack leading to this location.
#[derive(Debug, Serialize, Deserialize)]
pub struct Stack {
    /// An array of stack frames that represents a sequence of calls, rendered in reverse
    /// chronological order, that comprise the call stack.
    pub frames: Vec<StackFrame>,
    /// A message relevant to this call stack.
    pub message: Option<Message>,
    /// Key/value pairs that provide additional information about the stack.
    pub properties: Option<PropertyBag>,
}

/// A function call within a stack trace.
#[derive(Debug, Serialize, Deserialize)]
pub struct StackFrame {
    /// The location to which this stack frame refers.
    pub location: Option<Location>,
    /// The name of the module that contains the code of this stack frame.
    pub module: Option<String>,
    /// The parameters of the call that is executing.
    pub parameters: Option<Vec<String>>,
    /// Key/value pairs that provide additional information about the stack frame.
    pub properties: Option<PropertyBag>,
    /// The thread identifier of the stack frame.
    #[serde(rename = "threadId")]
    pub thread_id: Option<i64>,
}

/// The location to which this stack frame refers.
///
/// A location within a programming artifact.
///
/// A code location associated with the node.
///
/// The code location.
///
/// Identifies the location associated with the suppression.
#[derive(Debug, Serialize, Deserialize)]
pub struct Location {
    /// A set of regions relevant to the location.
    pub annotations: Option<Vec<Region>>,
    /// Value that distinguishes this location from all other locations within a single result
    /// object.
    pub id: Option<i64>,
    /// The logical locations associated with the result.
    #[serde(rename = "logicalLocations")]
    pub logical_locations: Option<Vec<LogicalLocation>>,
    /// A message relevant to the location.
    pub message: Option<Message>,
    /// Identifies the artifact and region.
    #[serde(rename = "physicalLocation")]
    pub physical_location: Option<PhysicalLocation>,
    /// Key/value pairs that provide additional information about the location.
    pub properties: Option<PropertyBag>,
    /// An array of objects that describe relationships between this location and others.
    pub relationships: Option<Vec<LocationRelationship>>,
}

/// A region within an artifact where a result was detected.
///
/// Specifies a portion of the artifact that encloses the region. Allows a viewer to display
/// additional context around the region.
///
/// Specifies a portion of the artifact.
///
/// The region of the artifact to delete.
#[derive(Debug, Serialize, Deserialize)]
pub struct Region {
    /// The length of the region in bytes.
    #[serde(rename = "byteLength")]
    pub byte_length: Option<i64>,
    /// The zero-based offset from the beginning of the artifact of the first byte in the region.
    #[serde(rename = "byteOffset")]
    pub byte_offset: Option<i64>,
    /// The length of the region in characters.
    #[serde(rename = "charLength")]
    pub char_length: Option<i64>,
    /// The zero-based offset from the beginning of the artifact of the first character in the
    /// region.
    #[serde(rename = "charOffset")]
    pub char_offset: Option<i64>,
    /// The column number of the character following the end of the region.
    #[serde(rename = "endColumn")]
    pub end_column: Option<i64>,
    /// The line number of the last character in the region.
    #[serde(rename = "endLine")]
    pub end_line: Option<i64>,
    /// A message relevant to the region.
    pub message: Option<Message>,
    /// Key/value pairs that provide additional information about the region.
    pub properties: Option<PropertyBag>,
    /// The portion of the artifact contents within the specified region.
    pub snippet: Option<ArtifactContent>,
    /// Specifies the source language, if any, of the portion of the artifact specified by the
    /// region object.
    #[serde(rename = "sourceLanguage")]
    pub source_language: Option<String>,
    /// The column number of the first character in the region.
    #[serde(rename = "startColumn")]
    pub start_column: Option<i64>,
    /// The line number of the first character in the region.
    #[serde(rename = "startLine")]
    pub start_line: Option<i64>,
}

/// A logical location of a construct that produced a result.
#[derive(Debug, Serialize, Deserialize)]
pub struct LogicalLocation {
    /// The machine-readable name for the logical location, such as a mangled function name
    /// provided by a C++ compiler that encodes calling convention, return type and other details
    /// along with the function name.
    #[serde(rename = "decoratedName")]
    pub decorated_name: Option<String>,
    /// The human-readable fully qualified name of the logical location.
    #[serde(rename = "fullyQualifiedName")]
    pub fully_qualified_name: Option<String>,
    /// The index within the logical locations array.
    pub index: Option<i64>,
    /// The type of construct this logical location component refers to. Should be one of
    /// 'function', 'member', 'module', 'namespace', 'parameter', 'resource', 'returnType',
    /// 'type', 'variable', 'object', 'array', 'property', 'value', 'element', 'text',
    /// 'attribute', 'comment', 'declaration', 'dtd' or 'processingInstruction', if any of those
    /// accurately describe the construct.
    pub kind: Option<String>,
    /// Identifies the construct in which the result occurred. For example, this property might
    /// contain the name of a class or a method.
    pub name: Option<String>,
    /// Identifies the index of the immediate parent of the construct in which the result was
    /// detected. For example, this property might point to a logical location that represents
    /// the namespace that holds a type.
    #[serde(rename = "parentIndex")]
    pub parent_index: Option<i64>,
    /// Key/value pairs that provide additional information about the logical location.
    pub properties: Option<PropertyBag>,
}

/// Identifies the artifact and region.
///
/// A physical location relevant to a result. Specifies a reference to a programming artifact
/// together with a range of bytes or characters within that artifact.
#[derive(Debug, Serialize, Deserialize)]
pub struct PhysicalLocation {
    /// The address of the location.
    pub address: Option<Address>,
    /// The location of the artifact.
    #[serde(rename = "artifactLocation")]
    pub artifact_location: Option<ArtifactLocation>,
    /// Specifies a portion of the artifact that encloses the region. Allows a viewer to display
    /// additional context around the region.
    #[serde(rename = "contextRegion")]
    pub context_region: Option<Region>,
    /// Key/value pairs that provide additional information about the physical location.
    pub properties: Option<PropertyBag>,
    /// Specifies a portion of the artifact.
    pub region: Option<Region>,
}

/// Information about the relation of one location to another.
#[derive(Debug, Serialize, Deserialize)]
pub struct LocationRelationship {
    /// A description of the location relationship.
    pub description: Option<Message>,
    /// A set of distinct strings that categorize the relationship. Well-known kinds include
    /// 'includes', 'isIncludedBy' and 'relevant'.
    pub kinds: Option<Vec<String>>,
    /// Key/value pairs that provide additional information about the location relationship.
    pub properties: Option<PropertyBag>,
    /// A reference to the related location.
    pub target: i64,
}

/// A tool object that describes the converter.
///
/// The analysis tool that was run.
///
/// Information about the tool or tool pipeline that generated the results in this run. A run
/// can only contain results produced by a single tool or tool pipeline. A run can aggregate
/// results from multiple log files, as long as context around the tool run (tool
/// command-line arguments and the like) is identical for all aggregated files.
#[derive(Debug, Serialize, Deserialize)]
pub struct Tool {
    /// The analysis tool that was run.
    pub driver: ToolComponent,
    /// Tool extensions that contributed to or reconfigured the analysis tool that was run.
    pub extensions: Option<Vec<ToolComponent>>,
    /// Key/value pairs that provide additional information about the tool.
    pub properties: Option<PropertyBag>,
}

/// The analysis tool that was run.
///
/// A component, such as a plug-in or the driver, of the analysis tool that was run.
///
/// The analysis tool object that will be merged with a separate run.
#[derive(Debug, Serialize, Deserialize)]
pub struct ToolComponent {
    /// The component which is strongly associated with this component. For a translation, this
    /// refers to the component which has been translated. For an extension, this is the driver
    /// that provides the extension's plugin model.
    #[serde(rename = "associatedComponent")]
    pub associated_component: Option<ToolComponentReference>,
    /// The kinds of data contained in this object.
    pub contents: Option<Vec<Content>>,
    /// The binary version of the tool component's primary executable file expressed as four
    /// non-negative integers separated by a period (for operating systems that express file
    /// versions in this way).
    #[serde(rename = "dottedQuadFileVersion")]
    pub dotted_quad_file_version: Option<String>,
    /// The absolute URI from which the tool component can be downloaded.
    #[serde(rename = "downloadUri")]
    pub download_uri: Option<String>,
    /// A comprehensive description of the tool component.
    #[serde(rename = "fullDescription")]
    pub full_description: Option<MultiformatMessageString>,
    /// The name of the tool component along with its version and any other useful identifying
    /// information, such as its locale.
    #[serde(rename = "fullName")]
    pub full_name: Option<String>,
    /// A dictionary, each of whose keys is a resource identifier and each of whose values is a
    /// multiformatMessageString object, which holds message strings in plain text and
    /// (optionally) Markdown format. The strings can include placeholders, which can be used to
    /// construct a message in combination with an arbitrary number of additional string
    /// arguments.
    #[serde(rename = "globalMessageStrings")]
    pub global_message_strings: Option<HashMap<String, MultiformatMessageString>>,
    /// A unique identifer for the tool component in the form of a GUID.
    pub guid: Option<String>,
    /// The absolute URI at which information about this version of the tool component can be
    /// found.
    #[serde(rename = "informationUri")]
    pub information_uri: Option<String>,
    /// Specifies whether this object contains a complete definition of the localizable and/or
    /// non-localizable data for this component, as opposed to including only data that is
    /// relevant to the results persisted to this log file.
    #[serde(rename = "isComprehensive")]
    pub is_comprehensive: Option<bool>,
    /// The language of the messages emitted into the log file during this run (expressed as an
    /// ISO 639-1 two-letter lowercase language code) and an optional region (expressed as an ISO
    /// 3166-1 two-letter uppercase subculture code associated with a country or region). The
    /// casing is recommended but not required (in order for this data to conform to RFC5646).
    pub language: Option<String>,
    /// The semantic version of the localized strings defined in this component; maintained by
    /// components that provide translations.
    #[serde(rename = "localizedDataSemanticVersion")]
    pub localized_data_semantic_version: Option<String>,
    /// An array of the artifactLocation objects associated with the tool component.
    pub locations: Option<Vec<ArtifactLocation>>,
    /// The minimum value of localizedDataSemanticVersion required in translations consumed by
    /// this component; used by components that consume translations.
    #[serde(rename = "minimumRequiredLocalizedDataSemanticVersion")]
    pub minimum_required_localized_data_semantic_version: Option<String>,
    /// The name of the tool component.
    pub name: String,
    /// An array of reportingDescriptor objects relevant to the notifications related to the
    /// configuration and runtime execution of the tool component.
    pub notifications: Option<Vec<ReportingDescriptor>>,
    /// The organization or company that produced the tool component.
    pub organization: Option<String>,
    /// A product suite to which the tool component belongs.
    pub product: Option<String>,
    /// A localizable string containing the name of the suite of products to which the tool
    /// component belongs.
    #[serde(rename = "productSuite")]
    pub product_suite: Option<String>,
    /// Key/value pairs that provide additional information about the tool component.
    pub properties: Option<PropertyBag>,
    /// A string specifying the UTC date (and optionally, the time) of the component's release.
    #[serde(rename = "releaseDateUtc")]
    pub release_date_utc: Option<String>,
    /// An array of reportingDescriptor objects relevant to the analysis performed by the tool
    /// component.
    pub rules: Option<Vec<ReportingDescriptor>>,
    /// The tool component version in the format specified by Semantic Versioning 2.0.
    #[serde(rename = "semanticVersion")]
    pub semantic_version: Option<String>,
    /// A brief description of the tool component.
    #[serde(rename = "shortDescription")]
    pub short_description: Option<MultiformatMessageString>,
    /// An array of toolComponentReference objects to declare the taxonomies supported by the
    /// tool component.
    #[serde(rename = "supportedTaxonomies")]
    pub supported_taxonomies: Option<Vec<ToolComponentReference>>,
    /// An array of reportingDescriptor objects relevant to the definitions of both standalone
    /// and tool-defined taxonomies.
    pub taxa: Option<Vec<ReportingDescriptor>>,
    /// Translation metadata, required for a translation, not populated by other component types.
    #[serde(rename = "translationMetadata")]
    pub translation_metadata: Option<TranslationMetadata>,
    /// The tool component version, in whatever format the component natively provides.
    pub version: Option<String>,
}

/// Metadata that describes a specific report produced by the tool, as part of the analysis
/// it provides or its runtime reporting.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReportingDescriptor {
    /// Default reporting configuration information.
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: Option<ReportingConfiguration>,
    /// An array of unique identifies in the form of a GUID by which this report was known in
    /// some previous version of the analysis tool.
    #[serde(rename = "deprecatedGuids")]
    pub deprecated_guids: Option<Vec<String>>,
    /// An array of stable, opaque identifiers by which this report was known in some previous
    /// version of the analysis tool.
    #[serde(rename = "deprecatedIds")]
    pub deprecated_ids: Option<Vec<String>>,
    /// An array of readable identifiers by which this report was known in some previous version
    /// of the analysis tool.
    #[serde(rename = "deprecatedNames")]
    pub deprecated_names: Option<Vec<String>>,
    /// A description of the report. Should, as far as possible, provide details sufficient to
    /// enable resolution of any problem indicated by the result.
    #[serde(rename = "fullDescription")]
    pub full_description: Option<MultiformatMessageString>,
    /// A unique identifer for the reporting descriptor in the form of a GUID.
    pub guid: Option<String>,
    /// Provides the primary documentation for the report, useful when there is no online
    /// documentation.
    pub help: Option<MultiformatMessageString>,
    /// A URI where the primary documentation for the report can be found.
    #[serde(rename = "helpUri")]
    pub help_uri: Option<String>,
    /// A stable, opaque identifier for the report.
    pub id: String,
    /// A set of name/value pairs with arbitrary names. Each value is a multiformatMessageString
    /// object, which holds message strings in plain text and (optionally) Markdown format. The
    /// strings can include placeholders, which can be used to construct a message in combination
    /// with an arbitrary number of additional string arguments.
    #[serde(rename = "messageStrings")]
    pub message_strings: Option<HashMap<String, MultiformatMessageString>>,
    /// A report identifier that is understandable to an end user.
    pub name: Option<String>,
    /// Key/value pairs that provide additional information about the report.
    pub properties: Option<PropertyBag>,
    /// An array of objects that describe relationships between this reporting descriptor and
    /// others.
    pub relationships: Option<Vec<ReportingDescriptorRelationship>>,
    /// A concise description of the report. Should be a single sentence that is understandable
    /// when visible space is limited to a single line of text.
    #[serde(rename = "shortDescription")]
    pub short_description: Option<MultiformatMessageString>,
}

/// Information about the relation of one reporting descriptor to another.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReportingDescriptorRelationship {
    /// A description of the reporting descriptor relationship.
    pub description: Option<Message>,
    /// A set of distinct strings that categorize the relationship. Well-known kinds include
    /// 'canPrecede', 'canFollow', 'willPrecede', 'willFollow', 'superset', 'subset', 'equal',
    /// 'disjoint', 'relevant', and 'incomparable'.
    pub kinds: Option<Vec<String>>,
    /// Key/value pairs that provide additional information about the reporting descriptor
    /// reference.
    pub properties: Option<PropertyBag>,
    /// A reference to the related reporting descriptor.
    pub target: ReportingDescriptorReference,
}

/// Translation metadata, required for a translation, not populated by other component
/// types.
///
/// Provides additional metadata related to translation.
#[derive(Debug, Serialize, Deserialize)]
pub struct TranslationMetadata {
    /// The absolute URI from which the translation metadata can be downloaded.
    #[serde(rename = "downloadUri")]
    pub download_uri: Option<String>,
    /// A comprehensive description of the translation metadata.
    #[serde(rename = "fullDescription")]
    pub full_description: Option<MultiformatMessageString>,
    /// The full name associated with the translation metadata.
    #[serde(rename = "fullName")]
    pub full_name: Option<String>,
    /// The absolute URI from which information related to the translation metadata can be
    /// downloaded.
    #[serde(rename = "informationUri")]
    pub information_uri: Option<String>,
    /// The name associated with the translation metadata.
    pub name: String,
    /// Key/value pairs that provide additional information about the translation metadata.
    pub properties: Option<PropertyBag>,
    /// A brief description of the translation metadata.
    #[serde(rename = "shortDescription")]
    pub short_description: Option<MultiformatMessageString>,
}

/// A network of nodes and directed edges that describes some aspect of the structure of the
/// code (for example, a call graph).
#[derive(Debug, Serialize, Deserialize)]
pub struct Graph {
    /// A description of the graph.
    pub description: Option<Message>,
    /// An array of edge objects representing the edges of the graph.
    pub edges: Option<Vec<Edge>>,
    /// An array of node objects representing the nodes of the graph.
    pub nodes: Option<Vec<Node>>,
    /// Key/value pairs that provide additional information about the graph.
    pub properties: Option<PropertyBag>,
}

/// Represents a directed edge in a graph.
#[derive(Debug, Serialize, Deserialize)]
pub struct Edge {
    /// A string that uniquely identifies the edge within its graph.
    pub id: String,
    /// A short description of the edge.
    pub label: Option<Message>,
    /// Key/value pairs that provide additional information about the edge.
    pub properties: Option<PropertyBag>,
    /// Identifies the source node (the node at which the edge starts).
    #[serde(rename = "sourceNodeId")]
    pub source_node_id: String,
    /// Identifies the target node (the node at which the edge ends).
    #[serde(rename = "targetNodeId")]
    pub target_node_id: String,
}

/// Represents a node in a graph.
#[derive(Debug, Serialize, Deserialize)]
pub struct Node {
    /// Array of child nodes.
    pub children: Option<Vec<Node>>,
    /// A string that uniquely identifies the node within its graph.
    pub id: String,
    /// A short description of the node.
    pub label: Option<Message>,
    /// A code location associated with the node.
    pub location: Option<Location>,
    /// Key/value pairs that provide additional information about the node.
    pub properties: Option<PropertyBag>,
}

/// A result produced by an analysis tool.
#[derive(Debug, Serialize, Deserialize)]
pub struct TrivyResult {
    /// Identifies the artifact that the analysis tool was instructed to scan. This need not be
    /// the same as the artifact where the result actually occurred.
    #[serde(rename = "analysisTarget")]
    pub analysis_target: Option<ArtifactLocation>,
    /// A set of artifacts relevant to the result.
    pub attachments: Option<Vec<Attachment>>,
    /// The state of a result relative to a baseline of a previous run.
    #[serde(rename = "baselineState")]
    pub baseline_state: Option<BaselineState>,
    /// An array of 'codeFlow' objects relevant to the result.
    #[serde(rename = "codeFlows")]
    pub code_flows: Option<Vec<CodeFlow>>,
    /// A stable, unique identifier for the equivalence class of logically identical results to
    /// which this result belongs, in the form of a GUID.
    #[serde(rename = "correlationGuid")]
    pub correlation_guid: Option<String>,
    /// A set of strings each of which individually defines a stable, unique identity for the
    /// result.
    pub fingerprints: Option<HashMap<String, String>>,
    /// An array of 'fix' objects, each of which represents a proposed fix to the problem
    /// indicated by the result.
    pub fixes: Option<Vec<Fix>>,
    /// An array of zero or more unique graph objects associated with the result.
    pub graphs: Option<Vec<Graph>>,
    /// An array of one or more unique 'graphTraversal' objects.
    #[serde(rename = "graphTraversals")]
    pub graph_traversals: Option<Vec<GraphTraversal>>,
    /// A stable, unique identifer for the result in the form of a GUID.
    pub guid: Option<String>,
    /// An absolute URI at which the result can be viewed.
    #[serde(rename = "hostedViewerUri")]
    pub hosted_viewer_uri: Option<String>,
    /// A value that categorizes results by evaluation state.
    pub kind: Option<ResultKind>,
    /// A value specifying the severity level of the result.
    pub level: Option<Level>,
    /// The set of locations where the result was detected. Specify only one location unless the
    /// problem indicated by the result can only be corrected by making a change at every
    /// specified location.
    pub locations: Option<Vec<Location>>,
    /// A message that describes the result. The first sentence of the message only will be
    /// displayed when visible space is limited.
    pub message: Message,
    /// A positive integer specifying the number of times this logically unique result was
    /// observed in this run.
    #[serde(rename = "occurrenceCount")]
    pub occurrence_count: Option<i64>,
    /// A set of strings that contribute to the stable, unique identity of the result.
    #[serde(rename = "partialFingerprints")]
    pub partial_fingerprints: Option<HashMap<String, String>>,
    /// Key/value pairs that provide additional information about the result.
    pub properties: Option<PropertyBag>,
    /// Information about how and when the result was detected.
    pub provenance: Option<ResultProvenance>,
    /// A number representing the priority or importance of the result.
    pub rank: Option<f64>,
    /// A set of locations relevant to this result.
    #[serde(rename = "relatedLocations")]
    pub related_locations: Option<Vec<Location>>,
    /// A reference used to locate the rule descriptor relevant to this result.
    pub rule: Option<ReportingDescriptorReference>,
    /// The stable, unique identifier of the rule, if any, to which this notification is
    /// relevant. This member can be used to retrieve rule metadata from the rules dictionary, if
    /// it exists.
    #[serde(rename = "ruleId")]
    pub rule_id: Option<String>,
    /// The index within the tool component rules array of the rule object associated with this
    /// result.
    #[serde(rename = "ruleIndex")]
    pub rule_index: Option<i64>,
    /// An array of 'stack' objects relevant to the result.
    pub stacks: Option<Vec<Stack>>,
    /// A set of suppressions relevant to this result.
    pub suppressions: Option<Vec<Suppression>>,
    /// An array of references to taxonomy reporting descriptors that are applicable to the
    /// result.
    pub taxa: Option<Vec<ReportingDescriptorReference>>,
    /// A web request associated with this result.
    #[serde(rename = "webRequest")]
    pub web_request: Option<WebRequest>,
    /// A web response associated with this result.
    #[serde(rename = "webResponse")]
    pub web_response: Option<WebResponse>,
    /// The URIs of the work items associated with this result.
    #[serde(rename = "workItemUris")]
    pub work_item_uris: Option<Vec<String>>,
}

/// An artifact relevant to a result.
#[derive(Debug, Serialize, Deserialize)]
pub struct Attachment {
    /// The location of the attachment.
    #[serde(rename = "artifactLocation")]
    pub artifact_location: ArtifactLocation,
    /// A message describing the role played by the attachment.
    pub description: Option<Message>,
    /// Key/value pairs that provide additional information about the attachment.
    pub properties: Option<PropertyBag>,
    /// An array of rectangles specifying areas of interest within the image.
    pub rectangles: Option<Vec<Rectangle>>,
    /// An array of regions of interest within the attachment.
    pub regions: Option<Vec<Region>>,
}

/// An area within an image.
#[derive(Debug, Serialize, Deserialize)]
pub struct Rectangle {
    /// The Y coordinate of the bottom edge of the rectangle, measured in the image's natural
    /// units.
    pub bottom: Option<f64>,
    /// The X coordinate of the left edge of the rectangle, measured in the image's natural units.
    pub left: Option<f64>,
    /// A message relevant to the rectangle.
    pub message: Option<Message>,
    /// Key/value pairs that provide additional information about the rectangle.
    pub properties: Option<PropertyBag>,
    /// The X coordinate of the right edge of the rectangle, measured in the image's natural
    /// units.
    pub right: Option<f64>,
    /// The Y coordinate of the top edge of the rectangle, measured in the image's natural units.
    pub top: Option<f64>,
}

/// A set of threadFlows which together describe a pattern of code execution relevant to
/// detecting a result.
#[derive(Debug, Serialize, Deserialize)]
pub struct CodeFlow {
    /// A message relevant to the code flow.
    pub message: Option<Message>,
    /// Key/value pairs that provide additional information about the code flow.
    pub properties: Option<PropertyBag>,
    /// An array of one or more unique threadFlow objects, each of which describes the progress
    /// of a program through a thread of execution.
    #[serde(rename = "threadFlows")]
    pub thread_flows: Vec<ThreadFlow>,
}

/// Describes a sequence of code locations that specify a path through a single thread of
/// execution such as an operating system or fiber.
#[derive(Debug, Serialize, Deserialize)]
pub struct ThreadFlow {
    /// An string that uniquely identifies the threadFlow within the codeFlow in which it occurs.
    pub id: Option<String>,
    /// Values of relevant expressions at the start of the thread flow that remain constant.
    #[serde(rename = "immutableState")]
    pub immutable_state: Option<HashMap<String, MultiformatMessageString>>,
    /// Values of relevant expressions at the start of the thread flow that may change during
    /// thread flow execution.
    #[serde(rename = "initialState")]
    pub initial_state: Option<HashMap<String, MultiformatMessageString>>,
    /// A temporally ordered array of 'threadFlowLocation' objects, each of which describes a
    /// location visited by the tool while producing the result.
    pub locations: Vec<ThreadFlowLocation>,
    /// A message relevant to the thread flow.
    pub message: Option<Message>,
    /// Key/value pairs that provide additional information about the thread flow.
    pub properties: Option<PropertyBag>,
}

/// A location visited by an analysis tool while simulating or monitoring the execution of a
/// program.
#[derive(Debug, Serialize, Deserialize)]
pub struct ThreadFlowLocation {
    /// An integer representing the temporal order in which execution reached this location.
    #[serde(rename = "executionOrder")]
    pub execution_order: Option<i64>,
    /// The Coordinated Universal Time (UTC) date and time at which this location was executed.
    #[serde(rename = "executionTimeUtc")]
    pub execution_time_utc: Option<String>,
    /// Specifies the importance of this location in understanding the code flow in which it
    /// occurs. The order from most to least important is "essential", "important",
    /// "unimportant". Default: "important".
    pub importance: Option<Importance>,
    /// The index within the run threadFlowLocations array.
    pub index: Option<i64>,
    /// A set of distinct strings that categorize the thread flow location. Well-known kinds
    /// include 'acquire', 'release', 'enter', 'exit', 'call', 'return', 'branch', 'implicit',
    /// 'false', 'true', 'caution', 'danger', 'unknown', 'unreachable', 'taint', 'function',
    /// 'handler', 'lock', 'memory', 'resource', 'scope' and 'value'.
    pub kinds: Option<Vec<String>>,
    /// The code location.
    pub location: Option<Location>,
    /// The name of the module that contains the code that is executing.
    pub module: Option<String>,
    /// An integer representing a containment hierarchy within the thread flow.
    #[serde(rename = "nestingLevel")]
    pub nesting_level: Option<i64>,
    /// Key/value pairs that provide additional information about the threadflow location.
    pub properties: Option<PropertyBag>,
    /// The call stack leading to this location.
    pub stack: Option<Stack>,
    /// A dictionary, each of whose keys specifies a variable or expression, the associated value
    /// of which represents the variable or expression value. For an annotation of kind
    /// 'continuation', for example, this dictionary might hold the current assumed values of a
    /// set of global variables.
    pub state: Option<HashMap<String, MultiformatMessageString>>,
    /// An array of references to rule or taxonomy reporting descriptors that are applicable to
    /// the thread flow location.
    pub taxa: Option<Vec<ReportingDescriptorReference>>,
    /// A web request associated with this thread flow location.
    #[serde(rename = "webRequest")]
    pub web_request: Option<WebRequest>,
    /// A web response associated with this thread flow location.
    #[serde(rename = "webResponse")]
    pub web_response: Option<WebResponse>,
}

/// A web request associated with this thread flow location.
///
/// Describes an HTTP request.
///
/// A web request associated with this result.
#[derive(Debug, Serialize, Deserialize)]
pub struct WebRequest {
    /// The body of the request.
    pub body: Option<ArtifactContent>,
    /// The request headers.
    pub headers: Option<HashMap<String, String>>,
    /// The index within the run.webRequests array of the request object associated with this
    /// result.
    pub index: Option<i64>,
    /// The HTTP method. Well-known values are 'GET', 'PUT', 'POST', 'DELETE', 'PATCH', 'HEAD',
    /// 'OPTIONS', 'TRACE', 'CONNECT'.
    pub method: Option<String>,
    /// The request parameters.
    pub parameters: Option<HashMap<String, String>>,
    /// Key/value pairs that provide additional information about the request.
    pub properties: Option<PropertyBag>,
    /// The request protocol. Example: 'http'.
    pub protocol: Option<String>,
    /// The target of the request.
    pub target: Option<String>,
    /// The request version. Example: '1.1'.
    pub version: Option<String>,
}

/// A web response associated with this thread flow location.
///
/// Describes the response to an HTTP request.
///
/// A web response associated with this result.
#[derive(Debug, Serialize, Deserialize)]
pub struct WebResponse {
    /// The body of the response.
    pub body: Option<ArtifactContent>,
    /// The response headers.
    pub headers: Option<HashMap<String, String>>,
    /// The index within the run.webResponses array of the response object associated with this
    /// result.
    pub index: Option<i64>,
    /// Specifies whether a response was received from the server.
    #[serde(rename = "noResponseReceived")]
    pub no_response_received: Option<bool>,
    /// Key/value pairs that provide additional information about the response.
    pub properties: Option<PropertyBag>,
    /// The response protocol. Example: 'http'.
    pub protocol: Option<String>,
    /// The response reason. Example: 'Not found'.
    #[serde(rename = "reasonPhrase")]
    pub reason_phrase: Option<String>,
    /// The response status code. Example: 451.
    #[serde(rename = "statusCode")]
    pub status_code: Option<i64>,
    /// The response version. Example: '1.1'.
    pub version: Option<String>,
}

/// A proposed fix for the problem represented by a result object. A fix specifies a set of
/// artifacts to modify. For each artifact, it specifies a set of bytes to remove, and
/// provides a set of new bytes to replace them.
#[derive(Debug, Serialize, Deserialize)]
pub struct Fix {
    /// One or more artifact changes that comprise a fix for a result.
    #[serde(rename = "artifactChanges")]
    pub artifact_changes: Vec<ArtifactChange>,
    /// A message that describes the proposed fix, enabling viewers to present the proposed
    /// change to an end user.
    pub description: Option<Message>,
    /// Key/value pairs that provide additional information about the fix.
    pub properties: Option<PropertyBag>,
}

/// A change to a single artifact.
#[derive(Debug, Serialize, Deserialize)]
pub struct ArtifactChange {
    /// The location of the artifact to change.
    #[serde(rename = "artifactLocation")]
    pub artifact_location: ArtifactLocation,
    /// Key/value pairs that provide additional information about the change.
    pub properties: Option<PropertyBag>,
    /// An array of replacement objects, each of which represents the replacement of a single
    /// region in a single artifact specified by 'artifactLocation'.
    pub replacements: Vec<Replacement>,
}

/// The replacement of a single region of an artifact.
#[derive(Debug, Serialize, Deserialize)]
pub struct Replacement {
    /// The region of the artifact to delete.
    #[serde(rename = "deletedRegion")]
    pub deleted_region: Region,
    /// The content to insert at the location specified by the 'deletedRegion' property.
    #[serde(rename = "insertedContent")]
    pub inserted_content: Option<ArtifactContent>,
    /// Key/value pairs that provide additional information about the replacement.
    pub properties: Option<PropertyBag>,
}

/// Represents a path through a graph.
#[derive(Debug, Serialize, Deserialize)]
pub struct GraphTraversal {
    /// A description of this graph traversal.
    pub description: Option<Message>,
    /// The sequences of edges traversed by this graph traversal.
    #[serde(rename = "edgeTraversals")]
    pub edge_traversals: Option<Vec<EdgeTraversal>>,
    /// Values of relevant expressions at the start of the graph traversal that remain constant
    /// for the graph traversal.
    #[serde(rename = "immutableState")]
    pub immutable_state: Option<HashMap<String, MultiformatMessageString>>,
    /// Values of relevant expressions at the start of the graph traversal that may change during
    /// graph traversal.
    #[serde(rename = "initialState")]
    pub initial_state: Option<HashMap<String, MultiformatMessageString>>,
    /// Key/value pairs that provide additional information about the graph traversal.
    pub properties: Option<PropertyBag>,
    /// The index within the result.graphs to be associated with the result.
    #[serde(rename = "resultGraphIndex")]
    pub result_graph_index: Option<i64>,
    /// The index within the run.graphs to be associated with the result.
    #[serde(rename = "runGraphIndex")]
    pub run_graph_index: Option<i64>,
}

/// Represents the traversal of a single edge during a graph traversal.
#[derive(Debug, Serialize, Deserialize)]
pub struct EdgeTraversal {
    /// Identifies the edge being traversed.
    #[serde(rename = "edgeId")]
    pub edge_id: String,
    /// The values of relevant expressions after the edge has been traversed.
    #[serde(rename = "finalState")]
    pub final_state: Option<HashMap<String, MultiformatMessageString>>,
    /// A message to display to the user as the edge is traversed.
    pub message: Option<Message>,
    /// Key/value pairs that provide additional information about the edge traversal.
    pub properties: Option<PropertyBag>,
    /// The number of edge traversals necessary to return from a nested graph.
    #[serde(rename = "stepOverEdgeCount")]
    pub step_over_edge_count: Option<i64>,
}

/// Information about how and when the result was detected.
///
/// Contains information about how and when a result was detected.
#[derive(Debug, Serialize, Deserialize)]
pub struct ResultProvenance {
    /// An array of physicalLocation objects which specify the portions of an analysis tool's
    /// output that a converter transformed into the result.
    #[serde(rename = "conversionSources")]
    pub conversion_sources: Option<Vec<PhysicalLocation>>,
    /// A GUID-valued string equal to the automationDetails.guid property of the run in which the
    /// result was first detected.
    #[serde(rename = "firstDetectionRunGuid")]
    pub first_detection_run_guid: Option<String>,
    /// The Coordinated Universal Time (UTC) date and time at which the result was first
    /// detected. See "Date/time properties" in the SARIF spec for the required format.
    #[serde(rename = "firstDetectionTimeUtc")]
    pub first_detection_time_utc: Option<String>,
    /// The index within the run.invocations array of the invocation object which describes the
    /// tool invocation that detected the result.
    #[serde(rename = "invocationIndex")]
    pub invocation_index: Option<i64>,
    /// A GUID-valued string equal to the automationDetails.guid property of the run in which the
    /// result was most recently detected.
    #[serde(rename = "lastDetectionRunGuid")]
    pub last_detection_run_guid: Option<String>,
    /// The Coordinated Universal Time (UTC) date and time at which the result was most recently
    /// detected. See "Date/time properties" in the SARIF spec for the required format.
    #[serde(rename = "lastDetectionTimeUtc")]
    pub last_detection_time_utc: Option<String>,
    /// Key/value pairs that provide additional information about the result.
    pub properties: Option<PropertyBag>,
}

/// A suppression that is relevant to a result.
#[derive(Debug, Serialize, Deserialize)]
pub struct Suppression {
    /// A stable, unique identifer for the suprression in the form of a GUID.
    pub guid: Option<String>,
    /// A string representing the justification for the suppression.
    pub justification: Option<String>,
    /// A string that indicates where the suppression is persisted.
    pub kind: SuppressionKind,
    /// Identifies the location associated with the suppression.
    pub location: Option<Location>,
    /// Key/value pairs that provide additional information about the suppression.
    pub properties: Option<PropertyBag>,
    /// A string that indicates the state of the suppression.
    pub state: Option<State>,
}

/// Describes a single run of an analysis tool, and contains the reported output of that run.
#[derive(Debug, Serialize, Deserialize)]
pub struct Run {
    /// Addresses associated with this run instance, if any.
    pub addresses: Option<Vec<Address>>,
    /// An array of artifact objects relevant to the run.
    pub artifacts: Option<Vec<Artifact>>,
    /// Automation details that describe this run.
    #[serde(rename = "automationDetails")]
    pub automation_details: Option<RunAutomationDetails>,
    /// The 'guid' property of a previous SARIF 'run' that comprises the baseline that was used
    /// to compute result 'baselineState' properties for the run.
    #[serde(rename = "baselineGuid")]
    pub baseline_guid: Option<String>,
    /// Specifies the unit in which the tool measures columns.
    #[serde(rename = "columnKind")]
    pub column_kind: Option<ColumnKind>,
    /// A conversion object that describes how a converter transformed an analysis tool's native
    /// reporting format into the SARIF format.
    pub conversion: Option<Conversion>,
    /// Specifies the default encoding for any artifact object that refers to a text file.
    #[serde(rename = "defaultEncoding")]
    pub default_encoding: Option<String>,
    /// Specifies the default source language for any artifact object that refers to a text file
    /// that contains source code.
    #[serde(rename = "defaultSourceLanguage")]
    pub default_source_language: Option<String>,
    /// References to external property files that should be inlined with the content of a root
    /// log file.
    #[serde(rename = "externalPropertyFileReferences")]
    pub external_property_file_references: Option<ExternalPropertyFileReferences>,
    /// An array of zero or more unique graph objects associated with the run.
    pub graphs: Option<Vec<Graph>>,
    /// Describes the invocation of the analysis tool.
    pub invocations: Option<Vec<Invocation>>,
    /// The language of the messages emitted into the log file during this run (expressed as an
    /// ISO 639-1 two-letter lowercase culture code) and an optional region (expressed as an ISO
    /// 3166-1 two-letter uppercase subculture code associated with a country or region). The
    /// casing is recommended but not required (in order for this data to conform to RFC5646).
    pub language: Option<String>,
    /// An array of logical locations such as namespaces, types or functions.
    #[serde(rename = "logicalLocations")]
    pub logical_locations: Option<Vec<LogicalLocation>>,
    /// An ordered list of character sequences that were treated as line breaks when computing
    /// region information for the run.
    #[serde(rename = "newlineSequences")]
    pub newline_sequences: Option<Vec<String>>,
    /// The artifact location specified by each uriBaseId symbol on the machine where the tool
    /// originally ran.
    #[serde(rename = "originalUriBaseIds")]
    pub original_uri_base_ids: Option<HashMap<String, ArtifactLocation>>,
    /// Contains configurations that may potentially override both
    /// reportingDescriptor.defaultConfiguration (the tool's default severities) and
    /// invocation.configurationOverrides (severities established at run-time from the command
    /// line).
    pub policies: Option<Vec<ToolComponent>>,
    /// Key/value pairs that provide additional information about the run.
    pub properties: Option<PropertyBag>,
    /// An array of strings used to replace sensitive information in a redaction-aware property.
    #[serde(rename = "redactionTokens")]
    pub redaction_tokens: Option<Vec<String>>,
    /// The set of results contained in an SARIF log. The results array can be omitted when a run
    /// is solely exporting rules metadata. It must be present (but may be empty) if a log file
    /// represents an actual scan.
    pub results: Option<Vec<TrivyResult>>,
    /// Automation details that describe the aggregate of runs to which this run belongs.
    #[serde(rename = "runAggregates")]
    pub run_aggregates: Option<Vec<RunAutomationDetails>>,
    /// A specialLocations object that defines locations of special significance to SARIF
    /// consumers.
    #[serde(rename = "specialLocations")]
    pub special_locations: Option<SpecialLocations>,
    /// An array of toolComponent objects relevant to a taxonomy in which results are categorized.
    pub taxonomies: Option<Vec<ToolComponent>>,
    /// An array of threadFlowLocation objects cached at run level.
    #[serde(rename = "threadFlowLocations")]
    pub thread_flow_locations: Option<Vec<ThreadFlowLocation>>,
    /// Information about the tool or tool pipeline that generated the results in this run. A run
    /// can only contain results produced by a single tool or tool pipeline. A run can aggregate
    /// results from multiple log files, as long as context around the tool run (tool
    /// command-line arguments and the like) is identical for all aggregated files.
    pub tool: Tool,
    /// The set of available translations of the localized data provided by the tool.
    pub translations: Option<Vec<ToolComponent>>,
    /// Specifies the revision in version control of the artifacts that were scanned.
    #[serde(rename = "versionControlProvenance")]
    pub version_control_provenance: Option<Vec<VersionControlDetails>>,
    /// An array of request objects cached at run level.
    #[serde(rename = "webRequests")]
    pub web_requests: Option<Vec<WebRequest>>,
    /// An array of response objects cached at run level.
    #[serde(rename = "webResponses")]
    pub web_responses: Option<Vec<WebResponse>>,
}

/// Automation details that describe this run.
///
/// Information that describes a run's identity and role within an engineering system process.
#[derive(Debug, Serialize, Deserialize)]
pub struct RunAutomationDetails {
    /// A stable, unique identifier for the equivalence class of runs to which this object's
    /// containing run object belongs in the form of a GUID.
    #[serde(rename = "correlationGuid")]
    pub correlation_guid: Option<String>,
    /// A description of the identity and role played within the engineering system by this
    /// object's containing run object.
    pub description: Option<Message>,
    /// A stable, unique identifer for this object's containing run object in the form of a GUID.
    pub guid: Option<String>,
    /// A hierarchical string that uniquely identifies this object's containing run object.
    pub id: Option<String>,
    /// Key/value pairs that provide additional information about the run automation details.
    pub properties: Option<PropertyBag>,
}

/// References to external property files that should be inlined with the content of a root
/// log file.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalPropertyFileReferences {
    /// An array of external property files containing run.addresses arrays to be merged with the
    /// root log file.
    pub addresses: Option<Vec<ExternalPropertyFileReference>>,
    /// An array of external property files containing run.artifacts arrays to be merged with the
    /// root log file.
    pub artifacts: Option<Vec<ExternalPropertyFileReference>>,
    /// An external property file containing a run.conversion object to be merged with the root
    /// log file.
    pub conversion: Option<ExternalPropertyFileReference>,
    /// An external property file containing a run.driver object to be merged with the root log
    /// file.
    pub driver: Option<ExternalPropertyFileReference>,
    /// An array of external property files containing run.extensions arrays to be merged with
    /// the root log file.
    pub extensions: Option<Vec<ExternalPropertyFileReference>>,
    /// An external property file containing a run.properties object to be merged with the root
    /// log file.
    #[serde(rename = "externalizedProperties")]
    pub externalized_properties: Option<ExternalPropertyFileReference>,
    /// An array of external property files containing a run.graphs object to be merged with the
    /// root log file.
    pub graphs: Option<Vec<ExternalPropertyFileReference>>,
    /// An array of external property files containing run.invocations arrays to be merged with
    /// the root log file.
    pub invocations: Option<Vec<ExternalPropertyFileReference>>,
    /// An array of external property files containing run.logicalLocations arrays to be merged
    /// with the root log file.
    #[serde(rename = "logicalLocations")]
    pub logical_locations: Option<Vec<ExternalPropertyFileReference>>,
    /// An array of external property files containing run.policies arrays to be merged with the
    /// root log file.
    pub policies: Option<Vec<ExternalPropertyFileReference>>,
    /// Key/value pairs that provide additional information about the external property files.
    pub properties: Option<PropertyBag>,
    /// An array of external property files containing run.results arrays to be merged with the
    /// root log file.
    pub results: Option<Vec<ExternalPropertyFileReference>>,
    /// An array of external property files containing run.taxonomies arrays to be merged with
    /// the root log file.
    pub taxonomies: Option<Vec<ExternalPropertyFileReference>>,
    /// An array of external property files containing run.threadFlowLocations arrays to be
    /// merged with the root log file.
    #[serde(rename = "threadFlowLocations")]
    pub thread_flow_locations: Option<Vec<ExternalPropertyFileReference>>,
    /// An array of external property files containing run.translations arrays to be merged with
    /// the root log file.
    pub translations: Option<Vec<ExternalPropertyFileReference>>,
    /// An array of external property files containing run.requests arrays to be merged with the
    /// root log file.
    #[serde(rename = "webRequests")]
    pub web_requests: Option<Vec<ExternalPropertyFileReference>>,
    /// An array of external property files containing run.responses arrays to be merged with the
    /// root log file.
    #[serde(rename = "webResponses")]
    pub web_responses: Option<Vec<ExternalPropertyFileReference>>,
}

/// An external property file containing a run.conversion object to be merged with the root
/// log file.
///
/// An external property file containing a run.driver object to be merged with the root log
/// file.
///
/// An external property file containing a run.properties object to be merged with the root
/// log file.
///
/// Contains information that enables a SARIF consumer to locate the external property file
/// that contains the value of an externalized property associated with the run.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalPropertyFileReference {
    /// A stable, unique identifer for the external property file in the form of a GUID.
    pub guid: Option<String>,
    /// A non-negative integer specifying the number of items contained in the external property
    /// file.
    #[serde(rename = "itemCount")]
    pub item_count: Option<i64>,
    /// The location of the external property file.
    pub location: Option<ArtifactLocation>,
    /// Key/value pairs that provide additional information about the external property file.
    pub properties: Option<PropertyBag>,
}

/// A specialLocations object that defines locations of special significance to SARIF
/// consumers.
///
/// Defines locations of special significance to SARIF consumers.
#[derive(Debug, Serialize, Deserialize)]
pub struct SpecialLocations {
    /// Provides a suggestion to SARIF consumers to display file paths relative to the specified
    /// location.
    #[serde(rename = "displayBase")]
    pub display_base: Option<ArtifactLocation>,
    /// Key/value pairs that provide additional information about the special locations.
    pub properties: Option<PropertyBag>,
}

/// Specifies the information necessary to retrieve a desired revision from a version control
/// system.
#[derive(Debug, Serialize, Deserialize)]
pub struct VersionControlDetails {
    /// A Coordinated Universal Time (UTC) date and time that can be used to synchronize an
    /// enlistment to the state of the repository at that time.
    #[serde(rename = "asOfTimeUtc")]
    pub as_of_time_utc: Option<String>,
    /// The name of a branch containing the revision.
    pub branch: Option<String>,
    /// The location in the local file system to which the root of the repository was mapped at
    /// the time of the analysis.
    #[serde(rename = "mappedTo")]
    pub mapped_to: Option<ArtifactLocation>,
    /// Key/value pairs that provide additional information about the version control details.
    pub properties: Option<PropertyBag>,
    /// The absolute URI of the repository.
    #[serde(rename = "repositoryUri")]
    pub repository_uri: String,
    /// A string that uniquely and permanently identifies the revision within the repository.
    #[serde(rename = "revisionId")]
    pub revision_id: Option<String>,
    /// A tag that has been applied to the revision.
    #[serde(rename = "revisionTag")]
    pub revision_tag: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Role {
    #[serde(rename = "added")]
    Added,
    #[serde(rename = "analysisTarget")]
    AnalysisTarget,
    #[serde(rename = "attachment")]
    Attachment,
    #[serde(rename = "debugOutputFile")]
    DebugOutputFile,
    #[serde(rename = "deleted")]
    Deleted,
    #[serde(rename = "directory")]
    Directory,
    #[serde(rename = "driver")]
    Driver,
    #[serde(rename = "extension")]
    Extension,
    #[serde(rename = "memoryContents")]
    MemoryContents,
    #[serde(rename = "modified")]
    Modified,
    #[serde(rename = "policy")]
    Policy,
    #[serde(rename = "referencedOnCommandLine")]
    ReferencedOnCommandLine,
    #[serde(rename = "renamed")]
    Renamed,
    #[serde(rename = "responseFile")]
    ResponseFile,
    #[serde(rename = "resultFile")]
    ResultFile,
    #[serde(rename = "standardStream")]
    StandardStream,
    #[serde(rename = "taxonomy")]
    Taxonomy,
    #[serde(rename = "toolSpecifiedConfiguration")]
    ToolSpecifiedConfiguration,
    #[serde(rename = "tracedFile")]
    TracedFile,
    #[serde(rename = "translation")]
    Translation,
    #[serde(rename = "uncontrolled")]
    Uncontrolled,
    #[serde(rename = "unmodified")]
    Unmodified,
    #[serde(rename = "userSpecifiedConfiguration")]
    UserSpecifiedConfiguration,
}

/// Specifies the failure level for the report.
///
/// A value specifying the severity level of the notification.
///
/// A value specifying the severity level of the result.
#[derive(Debug, Serialize, Deserialize)]
pub enum Level {
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "none")]
    None,
    #[serde(rename = "note")]
    Note,
    #[serde(rename = "warning")]
    Warning,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Content {
    #[serde(rename = "localizedData")]
    LocalizedData,
    #[serde(rename = "nonLocalizedData")]
    NonLocalizedData,
}

/// The state of a result relative to a baseline of a previous run.
#[derive(Debug, Serialize, Deserialize)]
pub enum BaselineState {
    #[serde(rename = "absent")]
    Absent,
    #[serde(rename = "new")]
    New,
    #[serde(rename = "unchanged")]
    Unchanged,
    #[serde(rename = "updated")]
    Updated,
}

/// Specifies the importance of this location in understanding the code flow in which it
/// occurs. The order from most to least important is "essential", "important",
/// "unimportant". Default: "important".
#[derive(Debug, Serialize, Deserialize)]
pub enum Importance {
    #[serde(rename = "essential")]
    Essential,
    #[serde(rename = "important")]
    Important,
    #[serde(rename = "unimportant")]
    Unimportant,
}

/// A value that categorizes results by evaluation state.
#[derive(Debug, Serialize, Deserialize)]
pub enum ResultKind {
    #[serde(rename = "fail")]
    Fail,
    #[serde(rename = "informational")]
    Informational,
    #[serde(rename = "notApplicable")]
    NotApplicable,
    #[serde(rename = "open")]
    Open,
    #[serde(rename = "pass")]
    Pass,
    #[serde(rename = "review")]
    Review,
}

/// A string that indicates where the suppression is persisted.
#[derive(Debug, Serialize, Deserialize)]
pub enum SuppressionKind {
    #[serde(rename = "external")]
    External,
    #[serde(rename = "inSource")]
    InSource,
}

/// A string that indicates the state of the suppression.
#[derive(Debug, Serialize, Deserialize)]
pub enum State {
    #[serde(rename = "accepted")]
    Accepted,
    #[serde(rename = "rejected")]
    Rejected,
    #[serde(rename = "underReview")]
    UnderReview,
}

/// The SARIF format version of this external properties object.
///
/// The SARIF format version of this log file.
#[derive(Debug, Serialize, Deserialize)]
pub enum Version {
    #[serde(rename = "2.1.0")]
    The210,
}

/// Specifies the unit in which the tool measures columns.
#[derive(Debug, Serialize, Deserialize)]
pub enum ColumnKind {
    #[serde(rename = "unicodeCodePoints")]
    UnicodeCodePoints,
    #[serde(rename = "utf16CodeUnits")]
    Utf16CodeUnits,
}
