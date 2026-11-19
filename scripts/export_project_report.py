"""Export the Markdown project report to a formatted Word document."""

import re
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "project-report" / "report.md"
DESTINATION = ROOT / "docs" / "project-report" / "report.docx"
HEADING = re.compile(r"^(#{1,3})\s+(.*)$")
LIST_ITEM = re.compile(r"^\s*(?:[-*+]\s+|\d+\.\s+)(.*)$")
INLINE = re.compile(r"(\*\*.+?\*\*|`.+?`|\[[^\]]+\]\([^)]+\))")


def main() -> None:
    document = Document()
    section = document.sections[0]
    section.top_margin = Inches(0.8)
    section.bottom_margin = Inches(0.8)
    section.left_margin = Inches(1)
    section.right_margin = Inches(1)
    normal = document.styles["Normal"]
    normal.font.name = "Arial"
    normal.font.size = Pt(10.5)
    normal.paragraph_format.space_after = Pt(6)
    for style_name, size in (("Title", 22), ("Heading 1", 15), ("Heading 2", 12)):
        style = document.styles[style_name]
        style.font.name = "Arial"
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = RGBColor(21, 71, 66)

    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    paragraph_lines: list[str] = []
    for line in lines:
        heading = HEADING.match(line)
        list_item = LIST_ITEM.match(line)
        if not line.strip() or heading or list_item:
            _flush_paragraph(document, paragraph_lines)
        if not line.strip():
            continue
        if heading:
            level = len(heading.group(1))
            title = heading.group(2).strip()
            if level == 1:
                paragraph = document.add_paragraph(style="Title")
                paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                _add_inline(paragraph, title)
            else:
                _add_heading(document, title, min(level - 1, 2))
        elif list_item:
            style = "List Number" if re.match(r"^\s*\d+\.", line) else "List Bullet"
            paragraph = document.add_paragraph(style=style)
            _add_inline(paragraph, list_item.group(1).strip())
        else:
            paragraph_lines.append(line.strip())
    _flush_paragraph(document, paragraph_lines)

    document.core_properties.title = "SENTINEL Project Report"
    document.core_properties.subject = "Day 1–12 implementation and verified results"
    document.core_properties.keywords = "SENTINEL, NIDS, PCAP, Isolation Forest, hybrid detection"
    document.save(DESTINATION)


def _flush_paragraph(document: Document, lines: list[str]) -> None:
    if lines:
        paragraph = document.add_paragraph()
        _add_inline(paragraph, " ".join(lines))
        lines.clear()


def _add_heading(document: Document, text: str, level: int) -> None:
    paragraph = document.add_paragraph(style=f"Heading {level}")
    _add_inline(paragraph, text)


def _add_inline(paragraph, text: str) -> None:
    cursor = 0
    for match in INLINE.finditer(text):
        if match.start() > cursor:
            paragraph.add_run(text[cursor : match.start()])
        token = match.group()
        if token.startswith("**"):
            run = paragraph.add_run(token[2:-2])
            run.bold = True
        elif token.startswith("`"):
            run = paragraph.add_run(token[1:-1])
            run.font.name = "Courier New"
            run.font.size = Pt(9)
        else:
            link = re.fullmatch(r"\[([^\]]+)\]\(([^)]+)\)", token)
            paragraph.add_run(f"{link.group(1)} ({link.group(2)})")
        cursor = match.end()
    if cursor < len(text):
        paragraph.add_run(text[cursor:])


if __name__ == "__main__":
    main()
