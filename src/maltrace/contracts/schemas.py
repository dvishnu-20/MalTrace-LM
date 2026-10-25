from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class RawEvent(BaseModel):
    """
    Represents an un-normalized raw Windows trace event item.
    """
    sample_id: str = Field(..., description="Unique sample identifier")
    event_id: str = Field(..., description="Unique identifier for the event")
    event_order: int = Field(..., description="Sequential order index of event within trace")
    process_id: int = Field(..., description="Process ID (PID)")
    parent_process_id: int = Field(0, description="Parent Process ID (PPID)")
    timestamp: Optional[str] = Field(None, description="ISO timestamp or relative execution timestamp")
    api_name: str = Field(..., description="Win32/Native API or action name")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Raw event arguments")
    source_file: str = Field("unknown.json", description="Source file path or identifier")
    schema_version: str = Field("1.0.0", description="Contract schema version")


class RawTrace(BaseModel):
    """
    Collection of raw events from a JSON trace file.
    """
    sample_id: str
    events: List[RawEvent] = Field(default_factory=list)
    schema_version: str = "1.0.0"


class NormalizedEvent(BaseModel):
    """
    Normalized Windows execution event with categorized API, sanitized arguments, and collapse metadata.
    """
    sample_id: str = Field(..., description="Unique sample identifier")
    event_id: str = Field(..., description="Unique identifier for the event")
    event_order: int = Field(..., description="Sequential order index of event")
    process_id: int = Field(..., description="Process ID (PID)")
    parent_process_id: int = Field(0, description="Parent Process ID (PPID)")
    timestamp: Optional[str] = Field(None, description="Event timestamp")
    api_name: str = Field(..., description="Original Win32 API name")
    category: str = Field(..., description="Normalized category (e.g. process, registry, file, network, service, memory, synchronization, other)")
    safe_arguments: Dict[str, Any] = Field(default_factory=dict, description="Sanitized/safe argument key-values")
    source_file: str = Field(..., description="Source trace file name")
    schema_version: str = Field("1.0.0", description="Contract schema version")
    
    # Noise reduction & deduplication fields
    repeat_count: int = Field(1, description="Number of consecutive identical events collapsed")
    first_order: Optional[int] = Field(None, description="First order index before collapse")
    last_order: Optional[int] = Field(None, description="Last order index before collapse")
    first_timestamp: Optional[str] = Field(None, description="First event timestamp")
    last_timestamp: Optional[str] = Field(None, description="Last event timestamp")
    
    # Enhanced canonical normalization fields
    path_category: Optional[str] = Field(None, description="Safe path category (system_directory, user_directory, temporary_directory, application_data, startup_location, unknown)")
    is_persistence: bool = Field(False, description="True if event accesses persistence mechanisms like autostart registry keys")
    network_category: Optional[str] = Field(None, description="Network category (loopback, private, public, domain-like, unknown)")
    deterministic_hash: Optional[str] = Field(None, description="Deterministic event SHA-256 hash")


class ProcessSummary(BaseModel):
    """
    Behavioral summary for a specific process tree node.
    """
    process_id: int
    process_name: str
    parent_process_id: int
    event_ids: List[str] = Field(default_factory=list)
    categories_observed: List[str] = Field(default_factory=list)
    child_process_ids: List[int] = Field(default_factory=list)
    readable_path: Optional[str] = Field(None, description="Human-readable process lineage path string")
    is_root: bool = Field(False, description="Whether process is a root process in tree")
    is_orphan: bool = Field(False, description="Whether parent process was missing from trace")
    has_cycle: bool = Field(False, description="Whether process was involved in a cycle")


class ProcessTreeNode(BaseModel):
    """
    Process tree node definition.
    """
    process_id: int
    parent_process_id: int
    process_name: str
    image_path: Optional[str] = None
    command_line: Optional[str] = None
    child_pids: List[int] = Field(default_factory=list)
    is_root: bool = False
    is_orphan: bool = False
    has_cycle: bool = False
    readable_path: str = ""


class BehaviorClaim(BaseModel):
    """
    Structured description of observed behavior with evidence citations.
    """
    claim_id: str = Field(..., description="Unique claim identifier")
    description: str = Field(..., description="Concise behavior description")
    category: str = Field(..., description="Behavior category")
    evidence_event_ids: List[str] = Field(default_factory=list, description="Cited event IDs supporting claim")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence score")


class EvidenceReference(BaseModel):
    """
    Direct reference to an evidence event supporting analysis claims.
    """
    event_id: str
    event_order: int
    api_name: str
    category: str
    snippet: str


class FamilyPrediction(BaseModel):
    """
    Malware family prediction result.
    """
    family_name: str = Field(..., description="Predicted family or benign label")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    confidence_label: str = Field("High", description="Categorical confidence (High, Medium, Low)")
    rule_triggered: str = Field(..., description="Primary rule or model signal triggered")
    supporting_evidence_ids: List[str] = Field(default_factory=list, description="Cited event IDs for prediction")
    top_class_probabilities: Dict[str, float] = Field(default_factory=dict, description="Calibrated probabilities or scores for candidate families")
    model_version: Optional[str] = Field(None, description="Model baseline version or name if predicted by ML model")



class TechniquePrediction(BaseModel):
    """
    MITRE ATT&CK technique mapping result with verified evidence links and explanation.
    """
    technique_id: str = Field(..., description="MITRE ATT&CK Technique ID (e.g., T1486)")
    technique_name: str = Field(..., description="Name of the technique")
    tactic: str = Field(..., description="MITRE ATT&CK Tactic (e.g. Impact, Persistence)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    confidence_label: str = Field("High", description="Categorical confidence (High, Medium, Low, Needs Review)")
    supporting_evidence_ids: List[str] = Field(..., min_length=1, description="Non-empty list of cited event IDs supporting mapping")
    matched_rules: List[str] = Field(default_factory=list, description="Specific catalog patterns or rules matched")
    explanation: str = Field("Matched observed execution trace pattern.", description="Human-readable explanation of why mapping triggered")
    needs_review: bool = Field(False, description="True if technique mapping is ambiguous or near benign thresholds")



class IngestionFileManifest(BaseModel):
    """
    Manifest entry for a single ingested trace file.
    """
    source_path: str
    file_size_bytes: int
    parse_status: str = Field("success", description="Status: success, partial, or failed")
    event_count: int = 0
    raw_event_count: int = 0
    process_count: int = 0
    warnings: List[str] = Field(default_factory=list)
    sha256: str
    sample_id: Optional[str] = None
    label: Optional[str] = None
    vocabulary_version: str = "1.0.0"


class BatchRunManifest(BaseModel):
    """
    Overall manifest recording batch execution results across files.
    """
    run_id: str
    timestamp: str
    total_files: int
    successful_files: int
    failed_files: int
    files: List[IngestionFileManifest] = Field(default_factory=list)
    vocabulary_version: str = "1.0.0"


class RunManifest(BaseModel):
    """
    Metadata recording execution environment, parameters, and optional LLM prompt versioning.
    """
    run_id: str
    timestamp: str
    maltrace_version: str = "0.1.0"
    vocabulary_version: str = "1.0.0"
    prompt_version: str = "1.0.0"
    input_file: str
    output_file: Optional[str] = None
    execution_time_ms: float
    seed: int = 42
    llm_provider: str = Field("disabled", description="LLM provider name: disabled, openai-compatible, mock")
    llm_model: Optional[str] = Field(None, description="LLM model identifier")
    temperature: float = Field(0.0, ge=0.0, le=2.0, description="LLM generation temperature")
    response_hash: Optional[str] = Field(None, description="SHA-256 hash of LLM response")
    validation_status: str = Field("disabled", description="Validation status: passed, failed, disabled")
    validation_warnings: List[str] = Field(default_factory=list, description="Warnings issued during grounding validation")


class LLMReportRequest(BaseModel):
    """
    Structured facts payload sent to optional LLM provider. Privacy safe: contains NO unredacted raw traces.
    """
    sample_id: str
    predicted_family: str
    confidence: float
    confidence_label: str
    rule_triggered: str
    behavior_categories: List[str]
    attack_techniques: List[Dict[str, Any]]
    process_summaries: List[Dict[str, Any]]
    controlled_phrases: List[Dict[str, Any]]
    cited_event_ids: List[str]


class LLMReportResponse(BaseModel):
    """
    Strict JSON output schema required from LLM provider.
    """
    summary: str = Field(..., description="High-level executive summary of observed malware behavior")
    behavior_claims: List[str] = Field(..., description="List of validated behavior claim statements")
    cited_event_ids: List[str] = Field(..., description="Non-empty list of cited event IDs supporting summary")
    uncertainty_statement: str = Field(..., description="Statement of uncertainties or gaps")
    analyst_notes: str = Field(..., description="Analyst guidance and recommended defensive actions")


class VerificationSummary(BaseModel):
    """
    Audit metrics produced by the Evidence Verifier.
    """
    total_claims: int = Field(0, description="Total behavior claims analyzed")
    supported_claims: int = Field(0, description="Number of fully supported claims")
    partially_supported_claims: int = Field(0, description="Number of partially supported claims")
    rejected_claims: int = Field(0, description="Number of rejected claims")
    citation_completeness: float = Field(1.0, ge=0.0, le=1.0, description="Ratio of valid cited event references")
    family_abstained: bool = Field(False, description="Whether family classification was abstained")
    abstention_reason: Optional[str] = Field(None, description="Reason for family prediction abstention")
    rejected_claim_details: List[Dict[str, Any]] = Field(default_factory=list, description="Audit record of rejected claims")


class AnalystReport(BaseModel):
    """
    Complete analyst report containing executive summary, family prediction, observed categories,
    ATT&CK techniques, process tree overview, evidence table, uncertainty, and limitations.
    """
    sample_id: str
    generation_mode: str = Field("deterministic", description="Generation mode: deterministic or llm")
    executive_summary: str
    predicted_family: str
    confidence: float
    confidence_label: str
    signal_triggered: str
    observed_categories: List[str]
    attack_techniques: List[TechniquePrediction] = Field(default_factory=list)
    process_tree_overview: List[Dict[str, Any]] = Field(default_factory=list)
    key_evidence_table: List[EvidenceReference] = Field(default_factory=list)
    uncertainty_and_limitations: str
    analyst_recommendations: List[str] = Field(default_factory=list)
    verification_summary: Optional[VerificationSummary] = None
    manifest: Optional[RunManifest] = None
    schema_version: str = "1.0.0"


class BehaviorStatement(BaseModel):
    """
    Controlled natural-language statement describing a single normalized event.
    """
    statement_id: str = Field(..., description="Unique statement identifier")
    sample_id: str = Field(..., description="Sample ID")
    process_id: int = Field(..., description="Process ID (PID)")
    event_id: str = Field(..., description="Source event ID link")
    event_order: int = Field(..., description="Sequential order index")
    category: str = Field(..., description="Behavior category")
    severity: str = Field("info", description="Severity hint (info, low, medium, high, critical)")
    rendered_phrase: str = Field(..., description="Controlled natural language description phrase")
    anchor_rules: List[str] = Field(default_factory=list, description="Security anchor rules selecting this statement")
    candidate_attack_techniques: List[str] = Field(default_factory=list, description="Candidate MITRE ATT&CK technique IDs")
    evidence_metadata: Dict[str, Any] = Field(default_factory=dict, description="Internal evidence citation metadata")


class ProcessBehaviorSummary(BaseModel):
    """
    Process-level behavior summary grouping statements in execution order.
    """
    process_id: int
    process_name: str
    parent_process_id: int
    readable_path: str
    parent_relationship: str
    event_counts: Dict[str, int] = Field(default_factory=dict)
    high_value_actions: List[str] = Field(default_factory=list)
    behavior_statements: List[BehaviorStatement] = Field(default_factory=list)


class TraceBehaviorSummary(BaseModel):
    """
    Trace-level summary containing roots, child processes, major categories, anchors, and top behavior statements.
    """
    sample_id: str
    root_process_ids: List[int] = Field(default_factory=list)
    child_process_ids: List[int] = Field(default_factory=list)
    major_categories: Dict[str, int] = Field(default_factory=dict)
    security_anchors: List[BehaviorStatement] = Field(default_factory=list)
    top_behavior_statements: List[BehaviorStatement] = Field(default_factory=list)
    process_summaries: List[ProcessBehaviorSummary] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """
    Complete analysis result for a trace sample.
    """
    sample_id: str
    trace_summary: Dict[str, Any]
    process_summaries: List[ProcessSummary] = Field(default_factory=list)
    behavior_claims: List[BehaviorClaim] = Field(default_factory=list)
    family_prediction: FamilyPrediction
    technique_predictions: List[TechniquePrediction] = Field(default_factory=list)
    cited_evidence: List[EvidenceReference] = Field(default_factory=list)
    verification_summary: Optional[VerificationSummary] = None
    manifest: Optional[RunManifest] = None
    schema_version: str = "1.0.0"




