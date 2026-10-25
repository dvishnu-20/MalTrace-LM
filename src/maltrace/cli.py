from pathlib import Path
from typing import Optional, List, Any
import json
import typer
from rich.console import Console
from rich.table import Table

from maltrace.reporting.generator import analyze_trace
from maltrace.ingestion.stream_parser import process_batch, stream_parse_file
from maltrace.reporting.audit import audit_dataset
from maltrace.representation.renderer import render_trace_statements
from maltrace.representation.grouping import build_trace_behavior_summary
from maltrace.representation.selector import DefaultBudgetSelector
from maltrace.representation.exporter import export_behavior_jsonl, export_behavior_text
from maltrace.models.trainer import train_model, predict_events_with_model, load_trained_model, compute_metrics, load_dataset_records
from maltrace.models.feature_extractor import extract_text_features, extract_structured_features

app = typer.Typer(
    name="maltrace",
    help="MalTrace-LM: Defensive Windows Trace Analysis & Behavioral Mapping CLI",
    add_completion=False,
    no_args_is_help=True
)
console = Console()


@app.command("analyze")
def analyze_cmd(
    input_path: Path = typer.Argument(
        ...,
        help="Path to JSON execution trace file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True
    ),
    out: Optional[Path] = typer.Option(
        None,
        "--out",
        "-o",
        help="Path to save generated analysis report JSON"
    ),
    seed: int = typer.Option(
        42,
        "--seed",
        "-s",
        help="Random seed for deterministic analysis"
    ),
    model_dir: Optional[Path] = typer.Option(
        None,
        "--model-dir",
        "-m",
        help="Path to trained model directory for family classification"
    )
):
    """
    Analyze a Windows execution trace JSON file and produce evidence-linked report.
    """
    console.print(f"[bold green]MalTrace-LM Analysis Engine v0.1.0[/bold green]")
    console.print(f"Analyzing input trace: [cyan]{input_path}[/cyan]")

    try:
        result = analyze_trace(input_file=input_path, output_file=out, seed=seed, model_dir=model_dir)

        fam = result.family_prediction
        console.print("\n" + "=" * 60)
        console.print(f"[bold yellow]Analysis Summary for Sample:[/bold yellow] [bold]{result.sample_id}[/bold]")
        console.print(f"  - Predicted Family: [bold red]{fam.family_name}[/bold red] (Confidence: {fam.confidence:.2f}, {fam.confidence_label})")
        console.print(f"  - Signal / Model Triggered: [italic]{fam.rule_triggered}[/italic]")
        console.print(f"  - Total Processes Analyzed: {len(result.process_summaries)}")
        console.print(f"  - Behavior Claims Extracted: {len(result.behavior_claims)}")
        console.print(f"  - ATT&CK Techniques Mapped: {len(result.technique_predictions)}")
        console.print(f"  - Evidence Events Cited: {len(result.cited_evidence)}")

        if result.verification_summary:
            v = result.verification_summary
            console.print("\n[bold blue]Evidence Verification Audit Summary:[/bold blue]")
            console.print(f"  - Total Claims Analyzed: {v.total_claims} (Supported: [green]{v.supported_claims}[/green], Partially: [yellow]{v.partially_supported_claims}[/yellow], Rejected: [red]{v.rejected_claims}[/red])")
            console.print(f"  - Citation Completeness: [green]{v.citation_completeness * 100:.1f}%[/green]")
            if v.family_abstained:
                console.print(f"  - Family Prediction Status: [bold red]ABSTAINED[/bold red] ({v.abstention_reason})")
            else:
                console.print("  - Family Prediction Status: [bold green]VALIDATED[/bold green]")

        if fam.top_class_probabilities:
            console.print("\n[bold magenta]Top Predicted Family Class Probabilities:[/bold magenta]")
            for class_name, prob in sorted(fam.top_class_probabilities.items(), key=lambda x: x[1], reverse=True)[:5]:
                console.print(f"  - {class_name}: {prob:.4f}")

        if result.technique_predictions:
            console.print("\n[bold cyan]MITRE ATT&CK Mapping:[/bold cyan]")
            for tech in result.technique_predictions:
                review_flag = " [bold yellow][NEEDS REVIEW][/bold yellow]" if tech.needs_review else ""
                console.print(f"  - [{tech.technique_id}] {tech.technique_name} (Tactic: {tech.tactic}, Conf: {tech.confidence:.2f}){review_flag}")
                console.print(f"    - Matched Rules: [dim]{', '.join(tech.matched_rules)}[/dim]")
                console.print(f"    - Supporting Events: [green]{', '.join(tech.supporting_evidence_ids)}[/green]")
                console.print(f"    - Explanation: {tech.explanation}")

        if out:
            console.print(f"\n[bold green]Report written successfully to:[/bold green] {out}")
        console.print("=" * 60)

    except Exception as e:
        console.print(f"[bold red]Analysis failed:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("report")
def report_cmd(
    input_path: Path = typer.Argument(
        ...,
        help="Path to JSON execution trace file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True
    ),
    format_type: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Report export format: 'json', 'markdown', or 'html'"
    ),
    out: Optional[Path] = typer.Option(
        None,
        "--out",
        "-o",
        help="Output file path to save report"
    ),
    enable_llm: bool = typer.Option(
        False,
        "--enable-llm",
        help="Enable optional LLM report enhancement provider"
    ),
    llm_provider: str = typer.Option(
        "disabled",
        "--llm-provider",
        help="LLM provider name: 'disabled', 'openai-compatible', or 'mock'"
    ),
    llm_endpoint: str = typer.Option(
        "http://localhost:11434/v1/chat/completions",
        "--llm-endpoint",
        help="OpenAI-compatible LLM endpoint URL"
    )
):
    """
    Generate an analyst report (JSON, Markdown, or HTML) for a trace sample.
    Runs 100% deterministically by default without an LLM.
    """
    console.print(f"[bold green]MalTrace-LM Report Generation Engine[/bold green]")
    console.print(f"Input Trace: [cyan]{input_path}[/cyan] | Format: [yellow]{format_type}[/yellow]")

    try:
        result = analyze_trace(input_file=input_path)

        provider = None
        if enable_llm and llm_provider == "openai-compatible":
            from maltrace.reporting.llm_provider import OpenAICompatibleLLMProvider
            provider = OpenAICompatibleLLMProvider(endpoint_url=llm_endpoint)
        elif enable_llm and llm_provider == "mock":
            from maltrace.reporting.llm_provider import MockLLMProvider
            provider = MockLLMProvider(mode="valid")
        else:
            from maltrace.reporting.llm_provider import DisabledLLMProvider
            provider = DisabledLLMProvider()

        from maltrace.reporting.grounding_gate import build_analyst_report
        from maltrace.reporting.report_generator import render_report_json, render_report_markdown, render_report_html

        report = build_analyst_report(result, llm_provider=provider)

        fmt_clean = format_type.lower().strip()
        if fmt_clean == "json":
            rendered = render_report_json(report)
        elif fmt_clean == "html":
            rendered = render_report_html(report)
        else:
            rendered = render_report_markdown(report)

        if out:
            out.parent.mkdir(parents=True, exist_ok=True)
            with open(out, "w", encoding="utf-8") as f:
                f.write(rendered)
            console.print(f"\n[bold green]Report written successfully to:[/bold green] {out}")
        else:
            console.print("\n" + "=" * 60)
            console.print(rendered)
            console.print("=" * 60)

    except Exception as e:
        console.print(f"[bold red]Report generation failed:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("batch")
def batch_cmd(
    input_path: Path = typer.Argument(
        ...,
        help="Path to single trace file or directory of trace files",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True
    ),
    out_dir: Path = typer.Option(
        Path("reports/batch_output"),
        "--out-dir",
        "-o",
        help="Directory to write normalized JSONL, Parquet, and manifest.json"
    )
):
    """
    Process trace files streamingly (one report at a time) and export normalized JSONL, Parquet, and manifest.
    """
    console.print(f"[bold green]MalTrace-LM Streaming Batch Ingestion Engine[/bold green]")
    console.print(f"Input: [cyan]{input_path}[/cyan] -> Output Directory: [cyan]{out_dir}[/cyan]")

    try:
        manifest = process_batch(input_path=input_path, output_dir=out_dir)

        console.print("\n" + "=" * 60)
        console.print(f"[bold yellow]Batch Processing Complete[/bold yellow]")
        console.print(f"  - Total Files Processed: {manifest.total_files}")
        console.print(f"  - Successful Files: [green]{manifest.successful_files}[/green]")
        console.print(f"  - Failed Files: [red]{manifest.failed_files}[/red]")

        table = Table(title="Ingestion File Summary")
        table.add_column("File Name", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Events", justify="right")
        table.add_column("Processes", justify="right")
        table.add_column("SHA-256", style="dim")

        for f in manifest.files:
            status_style = "green" if f.parse_status == "success" else ("yellow" if f.parse_status == "partial" else "red")
            table.add_row(
                Path(f.source_path).name,
                f"[{status_style}]{f.parse_status}[/{status_style}]",
                str(f.event_count),
                str(f.process_count),
                f.sha256[:12] + "..."
            )

        console.print(table)
        console.print(f"\n[bold green]Batch outputs written to:[/bold green] {out_dir}")
        console.print("=" * 60)

    except Exception as e:
        console.print(f"[bold red]Batch processing failed:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("render")
def render_cmd(
    input_path: Path = typer.Argument(
        ...,
        help="Path to single trace file or directory of trace files to render",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True
    ),
    out_dir: Path = typer.Option(
        Path("reports/render_output"),
        "--out-dir",
        "-o",
        help="Directory to write behavior_statements.jsonl and behavior_summary.txt"
    ),
    budget: int = typer.Option(
        2000,
        "--budget",
        "-b",
        help="Max character budget for behavior statement selection"
    )
):
    """
    Render trace events into controlled natural language behavior statements and process summaries with security anchor retention.
    """
    console.print(f"[bold green]MalTrace-LM Controlled Representation Engine[/bold green]")
    console.print(f"Rendering: [cyan]{input_path}[/cyan] (Budget: {budget} chars)\n")

    try:
        out_dir.mkdir(parents=True, exist_ok=True)

        if input_path.is_file():
            files_to_render = [input_path]
        else:
            files_to_render = sorted([
                p for p in input_path.glob("**/*")
                if p.is_file() and p.suffix.lower() in [".json", ".jsonl", ".ndjson"] and p.name != "manifest.json"
            ])

        for file_p in files_to_render:
            gen = stream_parse_file(file_p)
            events = []
            try:
                while True:
                    events.append(next(gen))
            except StopIteration:
                pass

            raw_stmts = render_trace_statements(events)
            selected_stmts = DefaultBudgetSelector.select(raw_stmts, max_budget_chars=budget)
            trace_summary = build_trace_behavior_summary(events, selected_stmts)

            base_name = file_p.stem
            jsonl_file = out_dir / f"{base_name}_behavior_statements.jsonl"
            txt_file = out_dir / f"{base_name}_behavior_summary.txt"

            export_behavior_jsonl(selected_stmts, jsonl_file)
            export_behavior_text(trace_summary, txt_file)

            anchors_count = sum(1 for s in selected_stmts if s.anchor_rules)

            console.print(f"[bold yellow]Sample rendered:[/bold yellow] [bold]{base_name}[/bold]")
            console.print(f"  - Total Events: {len(events)}")
            console.print(f"  - Statements Rendered: {len(raw_stmts)} -> Selected under budget: {len(selected_stmts)}")
            console.print(f"  - Preserved Security Anchors: [red]{anchors_count}[/red]")
            console.print(f"  - Written: [green]{jsonl_file.name}[/green] & [green]{txt_file.name}[/green]\n")

        console.print("=" * 60)

    except Exception as e:
        console.print(f"[bold red]Rendering failed:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("audit")
def audit_cmd(
    input_path: Path = typer.Argument(
        ...,
        help="Path to single trace file or directory of trace files to audit",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True
    )
):
    """
    Audit trace dataset reporting total files, failures, missing labels, event categories, trace lengths, and hash collisions.
    """
    console.print(f"[bold green]MalTrace-LM Quality Audit Engine[/bold green]")
    console.print(f"Auditing path: [cyan]{input_path}[/cyan]\n")

    try:
        report = audit_dataset(input_path=input_path)

        console.print("=" * 60)
        console.print(f"[bold yellow]Dataset Audit Summary[/bold yellow]")
        console.print(f"  - Total Files Audited: {report['total_files']}")
        console.print(f"  - Successful Parses: [green]{report['successful_files']}[/green]")
        console.print(f"  - Parse Failures: [red]{report['parse_failures']}[/red]")
        console.print(f"  - Missing Family Labels: [yellow]{report['missing_labels_count']}[/yellow]")
        console.print(f"  - Duplicated SHA-256 Hashes: {report['duplicate_hash_count']}")

        stats = report["trace_length_stats"]
        console.print(f"\n[bold cyan]Trace Length Distribution (Events/Trace):[/bold cyan]")
        console.print(f"  - Min: {stats['min']}, Max: {stats['max']}, Mean: {stats['mean']:.1f}, Median: {stats['median']:.1f}, P95: {stats['p95']:.1f}")

        cat_table = Table(title="Event Category Distribution")
        cat_table.add_column("Category", style="cyan")
        cat_table.add_column("Count", justify="right", style="green")

        for cat, count in report["category_distribution"].items():
            cat_table.add_row(cat, str(count))

        console.print(cat_table)

        if report["family_frequencies"]:
            fam_table = Table(title="Malware Family Frequencies")
            fam_table.add_column("Family Label", style="magenta")
            fam_table.add_column("Sample Count", justify="right", style="green")
            for fam, count in report["family_frequencies"].items():
                fam_table.add_row(fam, str(count))
            console.print(fam_table)

        console.print("=" * 60)

    except Exception as e:
        console.print(f"[bold red]Audit failed:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("train")
def train_cmd(
    data_path: Path = typer.Argument(
        ...,
        help="Path to training data directory or trace file",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True
    ),
    baseline: str = typer.Option(
        "tfidf",
        "--baseline",
        "-b",
        help="Model baseline name: 'tfidf', 'structured', or 'majority'"
    ),
    out_dir: Path = typer.Option(
        Path("models/family_model"),
        "--out-dir",
        "-o",
        help="Directory to save model artifacts"
    ),
    seed: int = typer.Option(
        42,
        "--seed",
        "-s",
        help="Random seed for hash-grouped splitting"
    ),
    balanced_subset: bool = typer.Option(
        False,
        "--balanced-subset",
        help="Enable small balanced development subset mode"
    )
):
    """
    Train a malware family classification model baseline on trace dataset.
    """
    console.print(f"[bold green]MalTrace-LM Model Training Engine[/bold green]")
    console.print(f"Data: [cyan]{data_path}[/cyan] | Baseline: [yellow]{baseline}[/yellow] | Output: [cyan]{out_dir}[/cyan]")

    try:
        res = train_model(
            input_path=data_path,
            output_model_dir=out_dir,
            baseline=baseline,
            seed=seed,
            balanced_subset=balanced_subset
        )

        cfg = res["config"]
        metrics = res["metrics"]

        console.print("\n" + "=" * 60)
        console.print(f"[bold yellow]Training & Evaluation Complete[/bold yellow]")
        console.print(f"  - Baseline: [bold]{cfg['baseline']}[/bold]")
        console.print(f"  - Total Labeled Samples: {cfg['total_samples']} (Excluded unknown: {cfg['excluded_unknown_samples']})")
        console.print(f"  - Train Split / Test Split: {cfg['train_samples']} / {cfg['test_samples']}")
        console.print(f"  - Split SHA-256 Hash: [dim]{cfg['split_hash']}[/dim]")
        console.print(f"  - Test Accuracy: [green]{metrics['accuracy']:.4f}[/green]")
        console.print(f"  - Balanced Accuracy: [green]{metrics['balanced_accuracy']:.4f}[/green]")
        console.print(f"  - Macro F1: [green]{metrics['macro_f1']:.4f}[/green]")

        console.print(f"\n[italic dim]{metrics['disclaimer']}[/italic dim]")
        console.print(f"\n[bold green]Model artifacts saved to:[/bold green] {out_dir}")
        console.print("=" * 60)

    except Exception as e:
        console.print(f"[bold red]Training failed:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("evaluate")
def evaluate_cmd(
    data_path: Path = typer.Argument(
        ...,
        help="Path to evaluation trace data",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True
    ),
    model_dir: Path = typer.Option(
        Path("models/family_model"),
        "--model-dir",
        "-m",
        help="Directory containing trained model artifacts"
    )
):
    """
    Evaluate a saved model artifact on an evaluation trace dataset.
    """
    console.print(f"[bold green]MalTrace-LM Model Evaluation Engine[/bold green]")
    console.print(f"Evaluating data: [cyan]{data_path}[/cyan] with model: [cyan]{model_dir}[/cyan]")

    try:
        model, config = load_trained_model(model_dir)
        records, excluded = load_dataset_records(data_path)

        if not records:
            console.print("[yellow]No labeled evaluation records found.[/yellow]")
            return

        baseline_type = config.get("baseline", "tfidf")
        if baseline_type == "tfidf":
            X_eval = extract_text_features(records)
        elif baseline_type == "structured":
            X_eval = extract_structured_features(records)
        else:
            X_eval = extract_text_features(records)

        y_true: List[str] = [r.label for r in records if r.label is not None]
        y_pred = model.predict(X_eval)

        metrics = compute_metrics(y_true, y_pred, list(model.classes_))

        console.print("\n" + "=" * 60)
        console.print(f"[bold yellow]Evaluation Metrics for Model ({baseline_type}):[/bold yellow]")
        console.print(f"  - Evaluated Samples: {len(records)} (Excluded unknown: {excluded})")
        console.print(f"  - Accuracy: [green]{metrics['accuracy']:.4f}[/green]")
        console.print(f"  - Balanced Accuracy: [green]{metrics['balanced_accuracy']:.4f}[/green]")
        console.print(f"  - Macro F1: [green]{metrics['macro_f1']:.4f}[/green]")
        console.print(f"  - Weighted F1: [green]{metrics['weighted_f1']:.4f}[/green]")
        console.print(f"\n[italic dim]{metrics['disclaimer']}[/italic dim]")
        console.print("=" * 60)

    except Exception as e:
        console.print(f"[bold red]Evaluation failed:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("predict")
def predict_cmd(
    input_path: Path = typer.Argument(
        ...,
        help="Path to JSON execution trace file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True
    ),
    model_dir: Path = typer.Option(
        Path("models/family_model"),
        "--model-dir",
        "-m",
        help="Directory containing trained model artifacts"
    )
):
    """
    Predict malware family for a trace file using saved model artifact.
    """
    console.print(f"[bold green]MalTrace-LM Model Inference Engine[/bold green]")
    console.print(f"Trace file: [cyan]{input_path}[/cyan] | Model: [cyan]{model_dir}[/cyan]")

    try:
        gen = stream_parse_file(input_path)
        events = list(gen)

        pred = predict_events_with_model(events, model_dir)

        console.print("\n" + "=" * 60)
        console.print(f"[bold yellow]Prediction Result for Sample:[/bold yellow] [bold]{input_path.stem}[/bold]")
        console.print(f"  - Predicted Family: [bold red]{pred.family_name}[/bold red]")
        console.print(f"  - Confidence: [bold]{pred.confidence:.4f}[/bold] ({pred.confidence_label})")
        console.print(f"  - Model Signal: [italic]{pred.rule_triggered}[/italic]")
        console.print(f"  - Supporting Evidence Event IDs: {pred.supporting_evidence_ids}")

        if pred.top_class_probabilities:
            console.print("\n[bold magenta]Class Probabilities:[/bold magenta]")
            for c_name, prob in sorted(pred.top_class_probabilities.items(), key=lambda x: x[1], reverse=True):
                console.print(f"  - {c_name}: {prob:.4f}")

        console.print("=" * 60)

    except Exception as e:
        console.print(f"[bold red]Prediction failed:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("version")
def version_cmd():
    """
    Display MalTrace-LM version information.
    """
    console.print("[bold green]MalTrace-LM Version 0.1.0[/bold green]")


@app.command("serve")
def serve_cmd(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host address to bind HTTP server"),
    port: int = typer.Option(8000, "--port", "-p", help="Port number to bind HTTP server"),
    reload: bool = typer.Option(False, "--reload", "-r", help="Enable auto-reload for development")
):
    """
    Launch production-style FastAPI web service for execution trace analysis.
    """
    import uvicorn
    console.print(f"[bold green]Starting MalTrace-LM FastAPI Service...[/bold green]")
    console.print(f"Listening on: [cyan]http://{host}:{port}[/cyan]")
    uvicorn.run("maltrace.api.app:app", host=host, port=port, reload=reload)


@app.command("cleanup")
def cleanup_cmd(
    max_age_days: int = typer.Option(30, "--max-age-days", "-d", help="Maximum age of analyses to retain in days")
):
    """
    Execute retention policy cleanup job removing old raw uploads and report artifacts.
    """
@app.command("diff")
def diff_cmd(
    trace_a: Path = typer.Argument(..., help="Path to first execution trace JSON", exists=True),
    trace_b: Path = typer.Argument(..., help="Path to second execution trace JSON", exists=True),
    json_out: bool = typer.Option(False, "--json", help="Output full differential report as JSON")
):
    """
    Perform differential comparison between two execution traces.
    """
    from maltrace.features.trace_diff import compute_trace_diff
    diff_res = compute_trace_diff(trace_a, trace_b)

    if json_out:
        console.print(diff_res.model_dump_json(indent=2))
        return

    console.print(f"[bold green]MalTrace-LM Multi-Trace Differential Engine[/bold green]")
    console.print(f"Comparing [cyan]{trace_a.name}[/cyan] vs [cyan]{trace_b.name}[/cyan]\n")
    console.print(f"[bold yellow]Behavioral Similarity Score:[/bold yellow] [bold]{diff_res.behavioral_similarity_score * 100:.1f}%[/bold]")
    console.print(f"  - Events: {diff_res.total_events_a} vs {diff_res.total_events_b}")
    console.print(f"  - Shared ATT&CK Techniques: [green]{', '.join(diff_res.shared_attack_techniques) or 'None'}[/green]")
    console.print(f"  - Unique Techniques (Trace A): [yellow]{', '.join(diff_res.unique_techniques_a) or 'None'}[/yellow]")
    console.print(f"  - Unique Techniques (Trace B): [yellow]{', '.join(diff_res.unique_techniques_b) or 'None'}[/yellow]")
    console.print(f"  - Shared Processes: [blue]{', '.join(diff_res.shared_processes) or 'None'}[/blue]")
    console.print(f"\n[italic]{diff_res.summary}[/italic]")


@app.command("export-navigator")
def export_navigator_cmd(
    input_path: Path = typer.Argument(..., help="Path to execution trace JSON", exists=True),
    out: Path = typer.Option(Path("reports/navigator_layer.json"), "--out", "-o", help="Path to save ATT&CK Navigator JSON layer")
):
    """
    Export an official MITRE ATT&CK Navigator v4.5 JSON layer from a trace analysis.
    """
    from maltrace.attack_mapping.navigator import export_navigator_layer_file
    console.print(f"[bold green]Exporting ATT&CK Navigator Layer...[/bold green]")
    result = analyze_trace(input_file=input_path)
    out_file = export_navigator_layer_file(result, output_path=out)
    console.print(f"[bold green]Navigator layer exported to:[/bold green] [cyan]{out_file}[/cyan]")
    console.print("Upload this file directly to https://mitre-attack.github.io/attack-navigator/")


@app.command("update-attack-catalog")
def update_catalog_cmd(
    source: Path = typer.Argument(..., help="Path to STIX 2.1 JSON enterprise bundle file", exists=True),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Output path for synchronized catalog JSON")
):
    """
    Synchronize the technique catalog with an external STIX 2.1 enterprise attack bundle.
    """
    from maltrace.attack_mapping.stix_sync import sync_catalog_from_stix
    console.print(f"[bold yellow]Synchronizing ATT&CK Catalog from STIX 2.1 source:[/bold yellow] [cyan]{source}[/cyan]")
    total = sync_catalog_from_stix(source, output_catalog_path=out)
    console.print(f"[bold green]Catalog synchronized successfully! Total techniques:[/bold green] [bold]{total}[/bold]")


@app.command("anomaly")
def anomaly_cmd(
    input_path: Path = typer.Argument(..., help="Path to execution trace JSON", exists=True)
):
    """
    Evaluate execution trace for zero-day behavioral anomalies and novel threat deviations.
    """
    from maltrace.ingestion.loader import load_trace_file
    from maltrace.representation.normalizer import normalize_trace_events
    from maltrace.models.anomaly import BehavioralAnomalyDetector

    raw = load_trace_file(input_path)
    norm = normalize_trace_events(raw.events)
    detector = BehavioralAnomalyDetector()
    res = detector.evaluate_trace(norm)

    console.print(f"[bold green]MalTrace-LM Behavioral Anomaly Detector[/bold green]")
    console.print(f"Sample: [cyan]{raw.sample_id}[/cyan]")
    console.print(f"  - Anomaly Score: [bold]{res['anomaly_score']:.3f}[/bold] ({res['confidence_label']})")
    status_str = "[bold red]ANOMALOUS / ZERO-DAY PROFILE[/bold red]" if res["is_anomaly"] else "[bold green]NORMAL EXECUTION PROFILE[/bold green]"
    console.print(f"  - Classification: {status_str}")
    if res["divergence_factors"]:
        console.print("  - Divergence Factors:")
        for factor in res["divergence_factors"]:
            console.print(f"    * {factor}")


@app.command("match-rules")
def match_rules_cmd(
    input_path: Path = typer.Argument(..., help="Path to execution trace JSON", exists=True),
    rules_file: Optional[Path] = typer.Option(None, "--rules", "-r", help="Path to custom Sigma JSON rules file")
):
    """
    Match behavioral detection / Sigma rules against an execution trace.
    """
    from maltrace.ingestion.loader import load_trace_file
    from maltrace.representation.normalizer import normalize_trace_events
    from maltrace.detection.sigma_matcher import BehavioralSigmaEngine

    raw = load_trace_file(input_path)
    norm = normalize_trace_events(raw.events)

    engine = BehavioralSigmaEngine()
    if rules_file:
        engine.load_rules_from_file(rules_file)

    matches = engine.evaluate_trace(norm)
    console.print(f"[bold green]MalTrace-LM Behavioral Rule Engine[/bold green]")
    console.print(f"Sample: [cyan]{raw.sample_id}[/cyan] ({len(norm)} events evaluated)")

    if not matches:
        console.print("[green]No behavioral Sigma rules matched this trace.[/green]")
        return

    console.print(f"\n[bold yellow]Matched Detection Rules ({len(matches)}):[/bold yellow]")
    for m in matches:
        lvl_color = "red" if m.level in ("critical", "high") else "yellow"
        console.print(f"  - [[bold {lvl_color}]{m.level.upper()}[/bold {lvl_color}]] [bold]{m.rule_id}[/bold]: {m.rule_title}")
        console.print(f"    - Description: {m.description}")
        console.print(f"    - Matched Event IDs ({m.matched_events_count}): [dim]{', '.join(m.matched_event_ids)}[/dim]")
        console.print(f"    - MITRE Tags: [cyan]{', '.join(m.tags)}[/cyan]")


@app.command("export-ids")
def export_ids_cmd(
    input_path: Path = typer.Argument(..., help="Path to execution trace JSON", exists=True),
    format_type: str = typer.Option("suricata", "--format", "-f", help="IDS format: 'suricata', 'snort', or 'zeek'"),
    output_path: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path")
):
    """
    Generate and export Suricata, Snort, or Zeek network intrusion detection rules from an execution trace.
    """
    from maltrace.reporting.generator import analyze_trace
    from maltrace.detection.ids_generator import export_ids_rules_from_result

    analysis_res = analyze_trace(input_path)
    rules_text = export_ids_rules_from_result(analysis_res, format_type=format_type, output_path=output_path)

    if output_path:
        console.print(f"[bold green]Exported {format_type.upper()} IDS rules to:[/bold green] [cyan]{output_path}[/cyan]")
    else:
        console.print(f"[bold green]Generated {format_type.upper()} IDS Rules:[/bold green]\n")
        console.print(rules_text)


@app.command("export-siem")
def export_siem_cmd(
    input_path: Path = typer.Argument(..., help="Path to execution trace JSON", exists=True),
    format_type: str = typer.Option("splunk", "--format", "-f", help="SIEM/TIP format: 'splunk', 'ecs', 'misp', or 'stix'"),
    output_path: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path")
):
    """
    Export threat intelligence objects for Splunk HEC, Elastic ECS, MISP, or STIX 2.1.
    """
    from maltrace.reporting.generator import analyze_trace
    from maltrace.reporting.siem_exporter import export_siem_format

    analysis_res = analyze_trace(input_path)
    siem_obj = export_siem_format(analysis_res, format_type=format_type, output_path=output_path)

    if output_path:
        console.print(f"[bold green]Exported {format_type.upper()} object to:[/bold green] [cyan]{output_path}[/cyan]")
    else:
        console.print_json(data=siem_obj)


@app.command("parse-sysmon")
def parse_sysmon_cmd(
    sysmon_file: Path = typer.Argument(..., help="Path to Sysmon XML or JSON event export", exists=True),
    output_path: Path = typer.Option(..., "--output", "-o", help="Path to write normalized MalTrace JSON trace")
):
    """
    Parse a native Windows Sysmon XML or JSON log export into canonical MalTrace JSON trace format.
    """
    import json
    from maltrace.ingestion.sysmon_adapter import parse_sysmon_xml, parse_sysmon_json

    if sysmon_file.suffix.lower() == ".xml":
        raw_trace = parse_sysmon_xml(sysmon_file)
    else:
        raw_trace = parse_sysmon_json(sysmon_file)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(raw_trace.model_dump(), f, indent=2)

    console.print(f"[bold green]Parsed Sysmon Log:[/bold green] [cyan]{len(raw_trace.events)} events[/cyan] converted.")
    console.print(f"Output saved to: [cyan]{output_path}[/cyan]")


@app.command("cluster-campaigns")
def cluster_campaigns_cmd(
    input_dir: Path = typer.Option(Path("data/samples"), "--input-dir", "-d", help="Directory containing trace JSON files"),
    distance_threshold: float = typer.Option(0.55, "--threshold", "-t", help="Distance clustering threshold")
):
    """
    Cluster a directory of execution traces to detect shared threat campaigns and infrastructure.
    """
    from maltrace.features.clustering import cluster_trace_samples

    sample_files: List[Any] = list(input_dir.glob("*.json"))
    if not sample_files:
        console.print(f"[bold red]No .json trace files found in {input_dir}[/bold red]")
        return

    console.print(f"[bold cyan]Clustering {len(sample_files)} trace samples in {input_dir}...[/bold cyan]")
    res = cluster_trace_samples(sample_files, distance_threshold=distance_threshold)

    console.print(f"\n[bold green]Campaign Clustering Summary:[/bold green]")
    console.print(f"Total Samples: [bold]{res.total_samples}[/bold] | Clusters Identified: [bold]{res.num_clusters}[/bold]\n")

    for cl in res.clusters:
        console.print(f"[bold yellow]=== {cl.cluster_label} ===[/bold yellow]")
        console.print(f"  - Samples ({cl.sample_count}): [cyan]{', '.join(cl.sample_ids)}[/cyan]")
        console.print(f"  - Cohesion Score: [bold]{cl.cohesion_score:.2f}[/bold]")
        if cl.shared_techniques:
            console.print(f"  - Shared ATT&CK: [dim]{', '.join(cl.shared_techniques)}[/dim]")
        if cl.shared_network_endpoints:
            console.print(f"  - Shared C2 / Endpoints: [red]{', '.join(cl.shared_network_endpoints)}[/red]")
        console.print("")


@app.command("predict-seq")
def predict_seq_cmd(
    input_path: Path = typer.Argument(..., help="Path to execution trace JSON", exists=True)
):
    """
    Classify trace using PyTorch Bidirectional LSTM with Self-Attention and extract attention heatmaps.
    """
    from maltrace.ingestion.loader import load_trace_file
    from maltrace.representation.normalizer import normalize_trace_events
    from maltrace.models.sequence_model import build_default_sequence_engine

    raw = load_trace_file(input_path)
    norm = normalize_trace_events(raw.events)

    engine = build_default_sequence_engine()
    res = engine.predict_trace(norm)

    console.print(f"[bold green]MalTrace-LM PyTorch BiLSTM Attention Model[/bold green]")
    console.print(f"Sample: [cyan]{raw.sample_id}[/cyan]")
    console.print(f"  - Predicted Family: [bold red]{res['predicted_family']}[/bold red]")
    console.print(f"  - Confidence: [bold]{res['confidence']*100:.1f}%[/bold]")

    if res["attention_highlights"]:
        console.print("\n[bold yellow]Top Self-Attention API Transitions (Key Decision Points):[/bold yellow]")
        for h in res["attention_highlights"]:
            anchor_tag = " [bold red][CRITICAL TRANSITION][/bold red]" if h["is_anchor"] else ""
            console.print(f"  - Event [dim]{h['event_id']}[/dim] ([cyan]{h['api_token']}[/cyan]) -> Weight: [bold]{h['attention_weight']:.4f}[/bold]{anchor_tag}")


@app.command("sync-stix")
def sync_stix_cmd(
    stix_file: Path = typer.Argument(..., help="Path to STIX 2.1 JSON enterprise bundle file", exists=True),
    catalog_path: Optional[Path] = typer.Option(None, "--catalog", "-c", help="Path to target catalog.json to update")
):
    """
    Synchronize the MalTrace-LM MITRE ATT&CK technique catalog against a STIX 2.1 JSON bundle.
    """
    import json
    from maltrace.attack_mapping.stix_sync import parse_stix_bundle, sync_catalog_from_stix

    with open(stix_file, "r", encoding="utf-8") as f:
        bundle_data = json.load(f)

    extracted = parse_stix_bundle(bundle_data)
    console.print(f"[bold green]Parsed STIX 2.1 Bundle:[/bold green] Found [cyan]{len(extracted)} valid attack-patterns[/cyan].")

    if catalog_path:
        total_count = sync_catalog_from_stix(stix_file, output_catalog_path=catalog_path)
        console.print(f"[bold green]Catalog Updated:[/bold green] [cyan]{total_count} techniques[/cyan] synchronized to [cyan]{catalog_path}[/cyan].")
    else:
        console.print("[dim]No --catalog specified to write updates. Displaying extracted techniques summary:[/dim]")
        for item in extracted[:10]:
            console.print(f"  - [cyan]{item['technique_id']}[/cyan] ({item['tactic']}): {item['name']}")
        if len(extracted) > 10:
            console.print(f"  ... and {len(extracted) - 10} more techniques.")


if __name__ == "__main__":
    app()


