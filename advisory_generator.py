import json
import os
import re
import logging
from io import BytesIO
from bs4 import BeautifulSoup

from groq import Groq, RateLimitError, APIStatusError, APIConnectionError
from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# Primary model + automatic fallback chain across Groq's separate per-model free-tier buckets
_PRIMARY_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
_FALLBACK_MODELS = [
    _PRIMARY_MODEL,
    "openai/gpt-oss-120b",
    "qwen/qwen3.8-27b",
    "openai/gpt-oss-20b",
]
MODEL_CHAIN = list(dict.fromkeys(_FALLBACK_MODELS))

SYSTEM_PROMPT = """You are a Senior Threat Intelligence and Cybersecurity Analyst writing formal security advisories (NCA format) for enterprise IT, SOC, and security operations teams.

Analyze the provided cybersecurity source material and produce a structured JSON object with EXACTLY these six string fields:

{
  "title": "Formal title prefixed with 'Critical Advisory: ' (if actively exploited, zero-day, CISA KEV, unauthenticated RCE, or CVSS >= 9.0) or 'Advisory: ' (for all other threats). Example: 'Critical Advisory: FortiBleed Credential Exposure Campaign Affecting Fortinet Firewalls and VPNs'",
  "overview": "A cohesive 2-4 sentence paragraph summarizing the threat or campaign, the vulnerability/attack vector (including CVE IDs and CVSS scores if mentioned), the threat actor (if known), and current real-world exploitation status.",
  "impact": "A cohesive 4-6 sentence paragraph detailing technical and operational consequences of a successful compromise — such as unauthorized administrative access, remote code execution, credential harvesting, lateral movement, persistence, malware/ransomware staging, or data exfiltration — contextualized to the role of the affected system.",
  "affected_products": "Newline-separated list (using \\n) of affected vendors, products, specific version ranges, or exposed configurations/environments. If no specific software version is named, describe the targeted infrastructure or exposure condition.",
  "preventive_measures": "Newline-separated list (using \\n) of 4-6 concrete, prioritized, and actionable remediation steps. Lead with the most direct fix (e.g., patching to specific fixed versions, rotating credentials, disabling exposed interfaces) followed by hardening, MFA/access controls, and log/IOC hunting.",
  "references": "Newline-separated list (using \\n) of plain URLs, starting with the source URL followed by any official vendor advisories, CVE/NVD links, or research blogs mentioned in the source."
}

STRICT FORMATTING & GROUNDING RULES:
1. Return ONLY a valid JSON object. All six values MUST be strings (never JSON arrays).
2. In "affected_products", "preventive_measures", and "references", separate each item with a single newline character (\\n). Do NOT prefix lines with bullets (-, *, •) or numbers (1., 2.) — the document renderer adds them automatically.
3. Never fabricate CVE IDs, version numbers, threat actor names, or URLs. Only cite identifiers and links present in the input.
4. For "impact" and "preventive_measures", combine facts from the article with standard enterprise security engineering principles appropriate for the vulnerability class and affected system."""

_BULLET_PREFIX_RE = re.compile(r"^(?:\d+[\.\)]\s*|[-•*▪▸]\s*)+")


def _clean_html(text: str) -> str:
    if not text or "<" not in text:
        return (text or "").strip()
    return " ".join(BeautifulSoup(text, "lxml").get_text(separator=" ", strip=True).split())


def _normalize_multiline_field(value, strip_bullets: bool = True) -> str:
    if isinstance(value, list):
        raw_lines = [str(item) for item in value]
    else:
        raw_lines = str(value or "").splitlines()

    cleaned_lines = []
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        if strip_bullets:
            line = _BULLET_PREFIX_RE.sub("", line).strip()
        if line:
            cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


def _call_groq_with_fallback(messages: list[dict]) -> str:
    last_error = None
    for model_id in MODEL_CHAIN:
        kwargs = {
            "model": model_id,
            "messages": messages,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }
        if model_id.startswith("openai/gpt-oss"):
            # Keep Chain-of-Thought reasoning minimal so it doesn't exhaust max_tokens or the 8k TPM free quota
            kwargs["reasoning_effort"] = "low"
            kwargs["max_tokens"] = 4096
        else:
            kwargs["max_tokens"] = 2500

        try:
            response = client.chat.completions.create(**kwargs)
            content = (response.choices[0].message.content or "").strip()
            if content:
                return content
        except (RateLimitError, APIConnectionError) as e:
            logging.warning(f"Groq model '{model_id}' hit rate/connection limit ({e}); trying next fallback model...")
            last_error = e
        except APIStatusError as e:
            if e.status_code in (429, 500, 502, 503, 504):
                logging.warning(f"Groq model '{model_id}' returned HTTP {e.status_code}; trying next fallback model...")
                last_error = e
            else:
                raise
    raise RuntimeError(f"All Groq models in fallback chain failed. Last error: {last_error}")


def generate_advisory_sections(
    title: str,
    url: str,
    source: str,
    article_text: str,
    description: str = "",
) -> dict:
    clean_desc = _clean_html(description)
    clean_article = (article_text or "").strip()

    context_parts = []
    if clean_desc:
        context_parts.append(f"Summary / Feed Metadata:\n{clean_desc}")
    if clean_article:
        context_parts.append(f"Full Article Content:\n{clean_article[:7500]}")
    if not context_parts:
        context_parts.append(f"Article Title Only:\n{title}")

    user_content = (
        f"Article Title: {title}\n"
        f"Source: {source}\n"
        f"Primary Source URL: {url}\n\n"
        + "\n\n".join(context_parts)
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]

    raw = _call_groq_with_fallback(messages)

    # Strip accidental markdown fences
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1].lstrip("json").strip() if len(parts) > 1 else raw

    try:
        sections = json.loads(raw)
    except json.JSONDecodeError:
        # Sanitise stray control characters (literal newlines inside JSON strings)
        cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', raw)
        sections = json.loads(cleaned)

    required = {"title", "overview", "impact", "affected_products", "preventive_measures", "references"}
    missing = required - sections.keys()
    if missing:
        raise ValueError(f"Groq response missing fields: {missing}")

    # Normalize all fields to clean strings and ensure primary URL is in references
    sections["title"] = str(sections["title"]).strip()
    sections["overview"] = " ".join(str(sections["overview"]).split())
    sections["impact"] = " ".join(str(sections["impact"]).split())
    sections["affected_products"] = _normalize_multiline_field(sections["affected_products"], strip_bullets=True)
    sections["preventive_measures"] = _normalize_multiline_field(sections["preventive_measures"], strip_bullets=True)
    sections["references"] = _normalize_multiline_field(sections["references"], strip_bullets=True)

    ref_lines = [line.strip() for line in sections["references"].splitlines() if line.strip()]
    if url and not any(url.rstrip("/") == r.rstrip("/") for r in ref_lines):
        ref_lines.insert(0, url)
    sections["references"] = "\n".join(ref_lines)

    return sections


# ---------------------------------------------------------------------------
# DOCX builder
# ---------------------------------------------------------------------------

_BG_HEADER = "0d1f3c"  # dark navy — header ID cell and section label rows
_BG_WHITE  = "ffffff"  # title cell and content rows
_FG_WHITE  = "ffffff"
_FG_BLUE   = "2563eb"  # title text colour
_FG_BODY   = "1a1a1a"  # body text

_COL_ID    = Inches(1.5)
_COL_TITLE = Inches(5.1)


def _set_cell_bg(cell, hex_color: str):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tcPr.append(shd)


def _make_run(para, text: str, bold: bool = False, color: str = _FG_BODY):
    run = para.add_run(text)
    run.bold = bold
    run.font.name = "Verdana"
    run.font.size = Pt(11)
    r, g, b = int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)
    run.font.color.rgb = RGBColor(r, g, b)


def _merged_row(table):
    row = table.add_row()
    return row.cells[0].merge(row.cells[1])


def _add_section_label(table, label: str):
    cell = _merged_row(table)
    cell.paragraphs[0].clear()
    _make_run(cell.paragraphs[0], label.upper(), bold=True, color=_FG_WHITE)
    _set_cell_bg(cell, _BG_HEADER)


def _add_content_text(table, text: str):
    cell = _merged_row(table)
    cell.paragraphs[0].clear()
    _make_run(cell.paragraphs[0], text.strip(), color=_FG_BODY)
    _set_cell_bg(cell, _BG_WHITE)


def _add_content_list(table, text: str, numbered: bool = False):
    cell = _merged_row(table)
    _set_cell_bg(cell, _BG_WHITE)
    items = [
        _BULLET_PREFIX_RE.sub("", line.strip()).strip()
        for line in text.strip().splitlines()
        if _BULLET_PREFIX_RE.sub("", line.strip()).strip()
    ]
    for i, item in enumerate(items):
        para = cell.paragraphs[0] if i == 0 else cell.add_paragraph()
        para.clear()
        para.paragraph_format.left_indent = Inches(0.2)
        prefix = f"{i + 1}.  " if numbered else "•  "
        _make_run(para, prefix + item, color=_FG_BODY)


def build_advisory_docx(sections: dict, advisory_id: str) -> bytes:
    doc = Document()

    for sec in doc.sections:
        sec.top_margin = Inches(0.9)
        sec.bottom_margin = Inches(0.9)
        sec.left_margin = Inches(1.0)
        sec.right_margin = Inches(1.0)

    for para in doc.paragraphs:
        para._element.getparent().remove(para._element)

    table = doc.add_table(rows=0, cols=2)
    table.style = "Table Grid"

    # ── Header row: ID | Title (2 columns) ─────────────────────────────────
    header_row = table.add_row()
    header_row.cells[0].width = _COL_ID
    header_row.cells[1].width = _COL_TITLE

    id_cell = header_row.cells[0]
    id_cell.paragraphs[0].clear()
    _make_run(id_cell.paragraphs[0], advisory_id, bold=True, color=_FG_WHITE)
    _set_cell_bg(id_cell, _BG_HEADER)

    title_cell = header_row.cells[1]
    title_cell.paragraphs[0].clear()
    _make_run(title_cell.paragraphs[0], sections.get("title", ""), bold=True, color=_FG_BLUE)
    _set_cell_bg(title_cell, _BG_WHITE)

    # ── Section rows (label + content, each full-width merged) ─────────────
    _add_section_label(table, "Overview")
    _add_content_text(table, sections.get("overview", ""))

    _add_section_label(table, "Impact")
    _add_content_text(table, sections.get("impact", ""))

    _add_section_label(table, "Affected Products")
    _add_content_list(table, sections.get("affected_products", ""), numbered=False)

    _add_section_label(table, "Preventive Measures")
    _add_content_list(table, sections.get("preventive_measures", ""), numbered=False)

    _add_section_label(table, "References")
    _add_content_list(table, sections.get("references", ""), numbered=True)

    buf = BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf.read()
