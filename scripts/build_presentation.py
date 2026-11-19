"""Build the SENTINEL project presentation from verified report assets."""

from __future__ import annotations

import json
from pathlib import Path

from PIL import Image
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Inches, Pt

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/project-report/SENTINEL-Presentation.pptx"
FIGURES = ROOT / "docs/project-report/figures"
EVALUATION = json.loads(
    (ROOT / "docs/evaluation/results/run-1-summary.json").read_text(encoding="utf-8")
)
NAVY = RGBColor(10, 20, 35)
TEAL = RGBColor(45, 212, 191)
WHITE = RGBColor(240, 246, 252)
MUTED = RGBColor(164, 180, 198)


def _metric_line(name: str) -> str:
    metric = EVALUATION["metrics"][name]
    matrix = str(metric["confusion_matrix"])
    return (
        f"{name.replace('_', ' ').title()}: {matrix} • "
        f"P/R/F1 = {metric['precision']:.3f}/{metric['recall']:.3f}/{metric['f1']:.3f} "
        f"• FPR = {metric['fpr']:.3f}"
    )


def main() -> None:
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    slides = [
        (
            "SENTINEL",
            "Intelligent Hybrid Network Intrusion Detection System",
            [
                "Final-year project",
                "Offline PCAP analysis • explainable evidence • analyst-led investigation",
            ],
            None,
        ),
        (
            "The problem",
            "Packet captures contain evidence, but are difficult to investigate",
            [
                "Packet-level detail obscures conversation patterns",
                "Rules are interpretable but threshold-dependent",
                "Anomaly detection finds unusual behavior, not necessarily attacks",
                "Analysts need provenance from alert back to capture evidence",
            ],
            None,
        ),
        (
            "Project objectives",
            "Build one traceable offline analysis workflow",
            [
                "Validate PCAP/PCAPNG input and extract metadata without payload storage",
                "Aggregate bidirectional flows and compute numeric features",
                "Combine configurable rules, Isolation Forest, and hybrid evidence",
                "Present analysis, events, incidents, and evaluation in a browser",
            ],
            None,
        ),
        (
            "Design boundary",
            "Offline NIDS, not an IPS",
            [
                "Processes authorized capture files",
                "Reports indicators and investigation evidence",
                "Does not block traffic or change firewall state",
                "No live capture, authentication, or multi-user authorization",
            ],
            None,
        ),
        (
            "System architecture",
            "Browser, API, relational records, managed artifacts",
            [
                "React + TypeScript application",
                "FastAPI validates requests and dispatches focused services",
                "MySQL stores analysis and detection records",
                "Private managed storage holds captures and generated model artifacts",
            ],
            "01-architecture.png",
        ),
        (
            "Capture workflow",
            "From an uploaded capture to an evidence-backed assessment",
            [
                "Content validation → packet metadata → bidirectional flows",
                "Rules and explicit-model inference run as separate stages",
                "Hybrid assessment consumes persisted selected results",
                "Pipeline orchestrates requested stages; it does not train implicitly",
            ],
            "02-pipeline.png",
        ),
        (
            "Bidirectional flows",
            "Summarize communication in a stable analysis-scoped record",
            [
                "Canonical endpoint ordering defines forward and backward direction",
                "Counts, bytes, timing, packet lengths, TCP flags, and rates",
                "Unavailable values remain missing; zero-duration rates are null",
                "Endpoint order does not infer client/server roles",
            ],
            "fig-04-traffic-analytics.png",
        ),
        (
            "Rule-based detection",
            "Three configurable, explainable rule categories",
            [
                "Multi-port probing by source/target context",
                "Capture-wide SYN-only packet volume",
                "Distinct TCP tuples with SYN-only traffic",
                "Findings include thresholds, explanation, and bounded flow evidence",
            ],
            "03-rules.png",
        ),
        (
            "Isolation Forest",
            "Unsupervised outlier detection over flow-v1 features",
            [
                "23 numeric flow features; identifiers and labels excluded",
                "Training uses explicitly selected completed analyses",
                "Median imputation + missingness flags; log1p; constant dimensions removed",
                "Anomaly score is not a probability of attack",
            ],
            "04-isolation-forest.png",
        ),
        (
            "Hybrid assessment",
            "Combine persisted evidence with visible provenance",
            [
                "Rule weights: Low 10, Medium 25, High 45, Critical 65",
                "Noisy-OR combines distinct rule contributions",
                "Within-analysis anomaly rank contributes 20–50; exact shared-flow bonus is 15",
                "Risk score prioritizes review; it is not compromise probability",
            ],
            "05-hybrid.png",
        ),
        (
            "Dashboard and analytics",
            "Historical capture analytics, not live monitoring",
            [
                "Analysis overview, packets, flows, findings, ML, hybrid, and pipeline",
                "Protocol distribution and adaptive packet-time buckets",
                "Scoped traffic summaries and event filters use persisted data",
                "Deep links preserve analysis and evidence context",
            ],
            "fig-04-traffic-analytics.png",
        ),
        (
            "Security events",
            "Keep rule, ML, and hybrid observations distinct",
            [
                "Event timestamps use the source record timestamp semantics",
                "ML indicators remain unrated: anomaly score is uncalibrated",
                "Evidence links return to source analysis and records",
                "Events are not automatically incidents",
            ],
            "fig-05-security-events.png",
        ),
        (
            "Incident investigation",
            "An analyst creates and maintains an investigation record",
            [
                "Attach existing evidence; original findings remain unchanged",
                "Status, priority, notes, and history are persisted",
                "No analyst identity is fabricated; actor fields remain nullable",
                "An incident is not an automatic confirmation of compromise",
            ],
            "06-incident.png",
        ),
        (
            "Evaluation design",
            "A reproducible, recipe-labelled synthetic benchmark",
            [
                f"Dataset: {EVALUATION['dataset_version']} • seed {EVALUATION['generation_seed']}",
                (
                    f"{EVALUATION['training_captures']} benign training captures; "
                    f"{EVALUATION['test_captures']} disjoint test captures"
                ),
                (
                    f"Test: {EVALUATION['test_benign_captures']} benign + "
                    f"{EVALUATION['test_suspicious_captures']} suspicious; labels assigned from recipes"
                ),
                f"{EVALUATION['repeat_count']} repeated benchmark runs; no public dataset or real traffic",
            ],
            "07-evaluation.png",
        ),
        (
            "Detection results",
            "Capture-level confusion matrices and metrics",
            [
                _metric_line("rule_only"),
                _metric_line("ml_only"),
                _metric_line("hybrid"),
                f"Matrix order: {EVALUATION['metrics']['confusion_matrix_order']} • synthetic only",
            ],
            None,
        ),
        (
            "What the results show",
            "The benchmark exposes tradeoffs, not generalization",
            [
                "Rule recipes were deliberately aligned with current rule logic",
                (
                    f"{EVALUATION['metrics']['ml_only']['fp']} ML/hybrid false positives: "
                    + ", ".join(EVALUATION["metrics"]["false_positive_samples"])
                ),
                "Hybrid preserved ML-only evidence and did not outperform ML here",
                (
                    f"{EVALUATION['metrics']['ml_only']['fn']} false negatives on this small recipe set; "
                    "not real-world accuracy"
                ),
            ],
            None,
        ),
        (
            "Processing benchmark",
            "Repeated local measurements on small synthetic captures",
            [
                (
                    f"{EVALUATION['test_packets']} packets • {EVALUATION['test_flows']} flows • "
                    f"{EVALUATION['test_capture_bytes']:,} capture bytes per pass"
                ),
                (
                    f"Median end-to-end: {EVALUATION['performance']['end_to_end_ms']['median']:.3f} "
                    f"ms/capture; mean: {EVALUATION['performance']['end_to_end_ms']['mean']:.3f} "
                    f"ms ({EVALUATION['performance']['repeated_capture_observations']} observations)"
                ),
                (
                    f"{EVALUATION['performance']['throughput_packets_per_second']:.2f} packets/s • "
                    f"{EVALUATION['performance']['throughput_flows_per_second']:.2f} flows/s"
                ),
                "Stage medians (ms): "
                + " • ".join(
                    f"{name.replace('_', ' ')} {duration:.3f}"
                    for name, duration in EVALUATION["performance"][
                        "stage_medians_ms"
                    ].items()
                    if name != "model_training"
                ),
            ],
            None,
        ),
        (
            "Security and quality",
            "Verified safeguards, with operational limits disclosed",
            [
                "100 MiB upload default; packet ceiling 100,000 by default, max 1,000,000",
                "Generated storage names; private managed storage; no model upload endpoint",
                "Backend tests 142; frontend tests 55 at Day 12 verification",
                "No auth; synchronous processing; two moderate React Router advisories remain",
            ],
            None,
        ),
        (
            "Limitations and next steps",
            "The prototype needs independent validation",
            [
                "Synthetic-only, capture-level benchmark; no public or real-world dataset",
                "No authentication, authorization, async workers, or retention policy",
                "Future: public labelled data, authorized traffic, calibration, access control",
                "Future ideas are unimplemented and require separate validation",
            ],
            None,
        ),
        (
            "Conclusion",
            "SENTINEL connects capture processing to analyst investigation",
            [
                "Implemented: parsing, flows, rules, ML, hybrid, analytics, incidents, evaluation",
                "Evidence provenance is preserved across the workflow",
                "Synthetic benchmark is reproducible but not production validation",
                "Questions",
            ],
            "fig-01-overview.png",
        ),
    ]
    for number, (title, subtitle, bullets, image) in enumerate(slides, start=1):
        slide = prs.slides.add_slide(prs.slide_layouts[6])
        _background(slide)
        _text(
            slide, 0.65, 0.35, 11.9, 0.55, title, 27 if number == 1 else 24, TEAL, True
        )
        if number == 1:
            _text(slide, 0.75, 1.75, 11.8, 0.9, subtitle, 31, WHITE, True)
            _text(slide, 0.78, 2.9, 11.3, 0.6, bullets[0], 18, MUTED)
            _text(slide, 0.78, 3.55, 11.3, 0.5, bullets[1], 16, TEAL)
            _text(
                slide,
                0.78,
                6.2,
                11.5,
                0.35,
                "Student and institution details: complete in the report before submission",
                12,
                MUTED,
            )
        else:
            _text(slide, 0.7, 1.05, 11.95, 0.75, subtitle, 20, WHITE, True)
            if image:
                _image(slide, image, 6.75, 2.0, 5.9, 4.55)
                text_width = 5.7
            else:
                text_width = 11.8
            y = 2.05
            for bullet in bullets:
                _bullet(slide, 0.82, y, text_width, bullet)
                y += 0.92 if len(bullet) > 95 else 0.75
        _text(
            slide,
            0.65,
            7.12,
            10.8,
            0.2,
            "SENTINEL  •  SYNTHETIC EVALUATION WHERE INDICATED",
            8,
            MUTED,
        )
        _text(
            slide,
            12.15,
            7.08,
            0.5,
            0.25,
            f"{number:02d}",
            10,
            TEAL,
            True,
            PP_ALIGN.RIGHT,
        )
    prs.core_properties.title = "SENTINEL — Final-Year Project Presentation"
    prs.core_properties.subject = (
        "Offline hybrid NIDS implementation and synthetic evaluation"
    )
    prs.core_properties.author = "[Student name]"
    prs.save(OUT)
    print(f"Wrote {OUT.relative_to(ROOT)} ({len(prs.slides)} slides)")


def _background(slide) -> None:
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = NAVY
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(0.16), Inches(7.5))
    shape.fill.solid()
    shape.fill.fore_color.rgb = TEAL
    shape.line.fill.background()


def _text(
    slide, x, y, w, h, value, size, color, bold=False, align=PP_ALIGN.LEFT
) -> None:
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    frame = box.text_frame
    frame.clear()
    frame.word_wrap = True
    frame.margin_left = Pt(0)
    frame.margin_right = Pt(0)
    frame.margin_top = Pt(0)
    frame.margin_bottom = Pt(0)
    paragraph = frame.paragraphs[0]
    paragraph.alignment = align
    run = paragraph.add_run()
    run.text = value
    run.font.name = "Aptos"
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = color


def _bullet(slide, x, y, width, value) -> None:
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE,
        Inches(x),
        Inches(y + 0.04),
        Inches(0.12),
        Inches(0.12),
    )
    shape.fill.solid()
    shape.fill.fore_color.rgb = TEAL
    shape.line.fill.background()
    box = slide.shapes.add_textbox(
        Inches(x + 0.28), Inches(y), Inches(width - 0.3), Inches(0.72)
    )
    frame = box.text_frame
    frame.clear()
    frame.word_wrap = True
    frame.vertical_anchor = MSO_ANCHOR.TOP
    frame.margin_left = 0
    frame.margin_right = 0
    frame.margin_top = 0
    frame.margin_bottom = 0
    p = frame.paragraphs[0]
    p.text = value
    p.font.name = "Aptos"
    p.font.size = Pt(17)
    p.font.color.rgb = WHITE


def _image(slide, filename, x, y, width, height) -> None:
    path = FIGURES / filename
    if not path.is_file():
        return
    with Image.open(path) as image:
        ratio = image.width / image.height
    box_ratio = width / height
    if ratio > box_ratio:
        actual_width, actual_height = width, width / ratio
    else:
        actual_width, actual_height = height * ratio, height
    left = x + (width - actual_width) / 2
    top = y + (height - actual_height) / 2
    slide.shapes.add_picture(
        str(path),
        Inches(left),
        Inches(top),
        width=Inches(actual_width),
        height=Inches(actual_height),
    )


if __name__ == "__main__":
    main()
