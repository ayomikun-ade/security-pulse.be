import json
import os
import logging
from io import BytesIO
from datetime import datetime

from groq import Groq
from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

SYSTEM_PROMPT = """You are a professional cybersecurity analyst writing formal security advisories for IT and security teams.

Given a news article about a cybersecurity threat, produce a structured advisory with exactly these six fields.
Return ONLY a valid JSON object — no markdown, no explanation, no code fences.

{
  "title": "Short professional title, e.g. 'Critical Advisory: ...' or 'Advisory: ...'",
  "overview": "2-3 sentences describing what happened, the threat actor or vulnerability, and current exploitation status.",
  "impact": "4-6 sentences on what a successful compromise enables — data theft, RCE, privilege escalation, etc.",
  "affected_products": "Newline-separated list of affected vendors, products, and versions.",
  "preventive_measures": "Newline-separated list of 4-6 concrete, actionable mitigation steps.",
  "references": "Newline-separated list of relevant URLs (include the source article URL)."
}

Write in formal, precise language. Do not speculate beyond what the article supports."""


def generate_advisory_sections(
    title: str,
    url: str,
    source: str,
    article_text: str,
    description: str = "",
) -> dict:
    body = article_text or description or title
    user_content = (
        f"Article Title: {title}\n"
        f"Source: {source}\n"
        f"URL: {url}\n\n"
        f"Article Content:\n{body[:7000]}"
    )

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        temperature=0.2,
        max_tokens=1500,
        response_format={"type": "json_object"},
    )

    raw = response.choices[0].message.content.strip()

    # Strip accidental markdown fences
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1].lstrip("json").strip() if len(parts) > 1 else raw

    try:
        sections = json.loads(raw)
    except json.JSONDecodeError:
        # Sanitise stray control characters (literal newlines inside JSON strings)
        import re
        cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', raw)
        sections = json.loads(cleaned)

    required = {"title", "overview", "impact", "affected_products", "preventive_measures", "references"}
    missing = required - sections.keys()
    if missing:
        raise ValueError(f"Groq response missing fields: {missing}")

    return sections


# ---------------------------------------------------------------------------
# DOCX builder
# ---------------------------------------------------------------------------

def _set_cell_bg(cell, hex_color: str):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tcPr.append(shd)


def _cell_para(cell, text: str, bold: bool = False, font_size: int = 11, color: str = None):
    cell.text = ""
    para = cell.paragraphs[0]
    run = para.add_run(text)
    run.bold = bold
    run.font.name = "Verdana"
    run.font.size = Pt(font_size)
    if color:
        r, g, b = int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)
        run.font.color.rgb = RGBColor(r, g, b)
    return para


def build_advisory_docx(sections: dict, advisory_id: str) -> bytes:
    doc = Document()

    for sec in doc.sections:
        sec.top_margin = Inches(0.9)
        sec.bottom_margin = Inches(0.9)
        sec.left_margin = Inches(1.0)
        sec.right_margin = Inches(1.0)

    # Remove default empty paragraph
    for para in doc.paragraphs:
        p = para._element
        p.getparent().remove(p)

    table = doc.add_table(rows=0, cols=2)
    table.style = "Table Grid"

    # Column widths: narrow label col, wide content col
    col_widths = [Inches(1.6), Inches(5.0)]

    def add_row(label: str, content: str, label_bg: str = "1a2b4a", label_color: str = "ffffff", content_bg: str = "f4f7fb"):
        row = table.add_row()
        row.cells[0].width = col_widths[0]
        row.cells[1].width = col_widths[1]

        _cell_para(row.cells[0], label, bold=True, font_size=11, color=label_color)
        _set_cell_bg(row.cells[0], label_bg)

        _cell_para(row.cells[1], content, font_size=11)
        _set_cell_bg(row.cells[1], content_bg)

        return row

    # Header row: ID + Title spanning full width via merge
    id_row = table.add_row()
    id_row.cells[0].width = col_widths[0]
    id_row.cells[1].width = col_widths[1]
    _cell_para(id_row.cells[0], advisory_id, bold=True, font_size=11, color="ffffff")
    _set_cell_bg(id_row.cells[0], "0d1f3c")
    _cell_para(id_row.cells[1], sections.get("title", ""), bold=True, font_size=11, color="ffffff")
    _set_cell_bg(id_row.cells[1], "0d1f3c")

    # Section rows
    rows_def = [
        ("Overview", "overview"),
        ("Impact", "impact"),
        ("Affected Products", "affected_products"),
        ("Preventive Measures", "preventive_measures"),
        ("References", "references"),
    ]

    for label, key in rows_def:
        add_row(label, sections.get(key, ""))

    # Footer row with date
    date_str = datetime.now().strftime("%B %d, %Y")
    footer_row = table.add_row()
    merged = footer_row.cells[0].merge(footer_row.cells[1])
    _cell_para(merged, f"Generated: {date_str}", font_size=9, color="666666")
    _set_cell_bg(merged, "eef1f5")

    buf = BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf.read()
