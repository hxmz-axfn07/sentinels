"""Export the Markdown project report to a styled Word document."""

from __future__ import annotations

import re
from pathlib import Path

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Mm, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "project-report" / "report.md"
DESTINATION = ROOT / "docs" / "project-report" / "report.docx"
HEADING = re.compile(r"^(#{1,3})\s+(.*)$")
LIST_ITEM = re.compile(r"^\s*(?:([-*+])\s+|(\d+)\.\s+)(.*)$")
IMAGE = re.compile(r"^!\[([^\]]*)\]\(([^)]+)\)$")
INLINE = re.compile(r"(\*\*.+?\*\*|\*[^*\n]+\*|`.+?`|\[[^\]]+\]\([^)]+\))")
TABLE_SEPARATOR = re.compile(
    r"^\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?$|^\|?\s*:?-{3,}:?\s*\|?$"
)


def main() -> None:
    document = Document()
    section = document.sections[0]
    section.page_width = Mm(210)
    section.page_height = Mm(297)
    section.top_margin = Inches(0.72)
    section.bottom_margin = Inches(0.72)
    section.left_margin = Inches(0.85)
    section.right_margin = Inches(0.85)

    _configure_styles(document)
    _configure_header_footer(section)

    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    toc_items = []
    for source_line in lines:
        source_heading = HEADING.match(source_line)
        if not source_heading:
            continue
        title = source_heading.group(2).strip()
        if title.startswith(("Chapter ", "Appendix ")) or title == "References":
            toc_items.append((len(source_heading.group(1)), title))
    paragraph_lines: list[str] = []
    index = 0
    inside_code = False
    code_lines: list[str] = []
    while index < len(lines):
        line = lines[index]
        if line.strip().startswith("```"):
            _flush_paragraph(document, paragraph_lines)
            if inside_code:
                _add_code_block(document, code_lines)
                code_lines.clear()
            inside_code = not inside_code
            index += 1
            continue
        if inside_code:
            code_lines.append(line)
            index += 1
            continue

        if line.strip().startswith("|"):
            _flush_paragraph(document, paragraph_lines)
            table_lines: list[str] = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                table_lines.append(lines[index])
                index += 1
            _add_markdown_table(document, table_lines)
            continue

        image = IMAGE.match(line.strip())
        heading = HEADING.match(line)
        list_item = LIST_ITEM.match(line)
        if (
            not line.strip()
            or heading
            or list_item
            or image
            or line.strip()
            in {
                "***",
                "---",
                r"\pagebreak",
                "[[AUTO_TOC]]",
            }
        ):
            _flush_paragraph(document, paragraph_lines)

        if not line.strip():
            index += 1
            continue
        if line.strip() in {"***", "---", r"\pagebreak"}:
            document.add_page_break()
        elif line.strip() == "[[AUTO_TOC]]":
            _add_toc_field(document, toc_items)
        elif heading:
            _add_markdown_heading(
                document, heading.group(2).strip(), len(heading.group(1))
            )
        elif list_item:
            if list_item.group(2):
                paragraph = document.add_paragraph()
                paragraph.paragraph_format.left_indent = Inches(0.25)
                paragraph.paragraph_format.first_line_indent = Inches(-0.25)
                paragraph.add_run(f"{list_item.group(2)}. ")
            else:
                paragraph = document.add_paragraph(style="List Bullet")
            _add_inline(paragraph, list_item.group(3).strip())
        elif image:
            _add_image(document, image.group(1).strip(), image.group(2).strip())
        elif line.lstrip().startswith(">"):
            paragraph = document.add_paragraph(style="Quote")
            _add_inline(paragraph, line.lstrip()[1:].strip())
        else:
            paragraph_lines.append(line.strip())
        index += 1

    _flush_paragraph(document, paragraph_lines)
    if inside_code:
        _add_code_block(document, code_lines)

    document.core_properties.title = "SENTINEL — Final-Year Project Report"
    document.core_properties.subject = (
        "Final report, implementation and measured evaluation results"
    )
    document.core_properties.author = "[Student name]"
    document.core_properties.keywords = (
        "SENTINEL, NIDS, PCAP, Isolation Forest, synthetic evaluation"
    )
    settings = document.settings.element
    update_fields = OxmlElement("w:updateFields")
    update_fields.set(qn("w:val"), "true")
    settings.append(update_fields)
    document.save(DESTINATION)
    print(f"Wrote {DESTINATION.relative_to(ROOT)}")


def _configure_styles(document: Document) -> None:
    styles = document.styles
    normal = styles["Normal"]
    normal.font.name = "Aptos"
    normal.font.size = Pt(10)
    normal.font.color.rgb = RGBColor(35, 47, 58)
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.12

    for name, size in (
        ("Title", 28),
        ("Subtitle", 15),
        ("Heading 1", 16),
        ("Heading 2", 12),
        ("Heading 3", 10.5),
    ):
        style = styles[name]
        style.font.name = "Aptos Display" if name != "Heading 3" else "Aptos"
        style.font.size = Pt(size)
        style.font.bold = name != "Subtitle"
        style.font.color.rgb = (
            RGBColor(14, 93, 91) if name != "Title" else RGBColor(13, 32, 52)
        )
        style.paragraph_format.keep_with_next = True
    styles["Heading 1"].paragraph_format.space_before = Pt(12)
    styles["Heading 2"].paragraph_format.space_before = Pt(9)
    styles["Heading 3"].paragraph_format.space_before = Pt(6)
    styles["Caption"].font.name = "Aptos"
    styles["Caption"].font.size = Pt(9)
    styles["Caption"].font.italic = True
    styles["Caption"].font.color.rgb = RGBColor(76, 91, 104)
    styles["Quote"].font.italic = True
    styles["Quote"].font.color.rgb = RGBColor(57, 76, 91)


def _configure_header_footer(section) -> None:
    header = section.header.paragraphs[0]
    header.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run = header.add_run("SENTINEL  |  FINAL-YEAR PROJECT REPORT")
    run.font.name = "Aptos"
    run.font.size = Pt(8)
    run.font.color.rgb = RGBColor(94, 112, 126)

    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.add_run("SENTINEL  •  ")
    _add_field(footer, "PAGE")
    footer.add_run(" of ")
    _add_field(footer, "NUMPAGES")


def _add_field(paragraph, instruction: str) -> None:
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    code = OxmlElement("w:instrText")
    code.set(qn("xml:space"), "preserve")
    code.text = f" {instruction} "
    separate = OxmlElement("w:fldChar")
    separate.set(qn("w:fldCharType"), "separate")
    placeholder = OxmlElement("w:t")
    placeholder.text = "1"
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run = OxmlElement("w:r")
    run.extend((begin, code, separate, placeholder, end))
    paragraph._p.append(run)


def _add_toc_field(document: Document, entries: list[tuple[int, str]]) -> None:
    paragraph = document.add_paragraph()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    code = OxmlElement("w:instrText")
    code.set(qn("xml:space"), "preserve")
    code.text = ' TOC \\o "1-3" \\h \\z \\u '
    separate = OxmlElement("w:fldChar")
    separate.set(qn("w:fldCharType"), "separate")
    start_run = OxmlElement("w:r")
    start_run.extend((begin, code, separate))
    paragraph._p.append(start_run)
    instruction_run = OxmlElement("w:r")
    instruction_text = OxmlElement("w:t")
    instruction_text.text = "Update this automatic contents field in Word or LibreOffice to add page numbers."
    instruction_run.append(instruction_text)
    paragraph._p.append(instruction_run)
    instruction_break = OxmlElement("w:r")
    instruction_break.append(OxmlElement("w:br"))
    paragraph._p.append(instruction_break)
    for level, title in entries:
        entry_run = OxmlElement("w:r")
        entry_text = OxmlElement("w:t")
        entry_text.set(qn("xml:space"), "preserve")
        entry_text.text = f"{'   ' if level > 2 else ''}{title}"
        entry_run.append(entry_text)
        paragraph._p.append(entry_run)
        break_run = OxmlElement("w:r")
        break_run.append(OxmlElement("w:br"))
        paragraph._p.append(break_run)
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    end_run = OxmlElement("w:r")
    end_run.append(end)
    paragraph._p.append(end_run)


def _add_markdown_heading(document: Document, title: str, markdown_level: int) -> None:
    if title.startswith(("Chapter ", "Appendix ")) or title == "References":
        document.add_page_break()
    if markdown_level == 1:
        paragraph = document.add_paragraph(style="Title")
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        _add_inline(paragraph, title)
    else:
        paragraph = document.add_heading(title, level=min(markdown_level - 1, 3))
        if title in {
            "Declaration",
            "Acknowledgements",
            "Abstract",
            "Table of Contents",
            "List of Figures",
            "List of Tables",
            "Abbreviations",
        }:
            paragraph.paragraph_format.page_break_before = True


def _add_image(document: Document, caption: str, relative_path: str) -> None:
    image_path = (SOURCE.parent / relative_path).resolve()
    if (
        not image_path.is_relative_to(SOURCE.parent.resolve())
        or not image_path.is_file()
    ):
        raise FileNotFoundError(
            f"Report image is missing or outside the report directory: {relative_path}"
        )
    paragraph = document.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph.paragraph_format.keep_with_next = True
    paragraph.add_run().add_picture(str(image_path), width=Inches(6.35))
    if caption:
        caption_paragraph = document.add_paragraph(style="Caption")
        caption_paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        _add_inline(caption_paragraph, caption)


def _add_markdown_table(document: Document, lines: list[str]) -> None:
    rows = []
    for line in lines:
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not TABLE_SEPARATOR.match(line.strip()):
            rows.append(cells)
    if not rows:
        return
    column_count = max(len(row) for row in rows)
    table = document.add_table(rows=1, cols=column_count)
    table.style = "Light Shading Accent 1"
    table.autofit = True
    table.rows[0]._tr.get_or_add_trPr().append(OxmlElement("w:tblHeader"))
    for row_index, cells in enumerate(rows):
        target = table.rows[0].cells if row_index == 0 else table.add_row().cells
        for column, cell in enumerate(target):
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            cell.text = ""
            paragraph = cell.paragraphs[0]
            paragraph.paragraph_format.space_after = Pt(2)
            value = cells[column] if column < len(cells) else ""
            _add_inline(paragraph, value)
            for run in paragraph.runs:
                run.font.size = Pt(8.5)
                if row_index == 0:
                    run.font.bold = True


def _add_code_block(document: Document, lines: list[str]) -> None:
    paragraph = document.add_paragraph()
    paragraph.paragraph_format.left_indent = Inches(0.18)
    paragraph.paragraph_format.right_indent = Inches(0.18)
    paragraph.paragraph_format.space_before = Pt(3)
    paragraph.paragraph_format.space_after = Pt(7)
    run = paragraph.add_run("\n".join(lines))
    run.font.name = "Consolas"
    run.font.size = Pt(8.5)
    run.font.color.rgb = RGBColor(35, 58, 75)


def _flush_paragraph(document: Document, lines: list[str]) -> None:
    if not lines:
        return
    text = " ".join(lines)
    lines.clear()
    if text.startswith("**") and text.endswith("**") and text.count("**") == 2:
        paragraph = document.add_paragraph()
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        _add_inline(paragraph, text)
        return
    if re.match(r"^(Figure|Table)\s+\d+\.", text):
        paragraph = document.add_paragraph(style="Caption")
        _add_inline(paragraph, text)
        return
    paragraph = document.add_paragraph()
    _add_inline(paragraph, text)


def _add_inline(paragraph, text: str) -> None:
    cursor = 0
    for match in INLINE.finditer(text):
        if match.start() > cursor:
            paragraph.add_run(text[cursor : match.start()])
        token = match.group()
        if token.startswith("**"):
            paragraph.add_run(token[2:-2]).bold = True
        elif token.startswith("*"):
            paragraph.add_run(token[1:-1]).italic = True
        elif token.startswith("`"):
            run = paragraph.add_run(token[1:-1])
            run.font.name = "Consolas"
            run.font.size = Pt(9)
        else:
            link = re.fullmatch(r"\[([^\]]+)\]\(([^)]+)\)", token)
            paragraph.add_run(f"{link.group(1)} ({link.group(2)})")
        cursor = match.end()
    if cursor < len(text):
        paragraph.add_run(text[cursor:])


if __name__ == "__main__":
    main()
