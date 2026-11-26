#!/usr/bin/env python3
"""Convert docs/user-manual.md into a formatted .docx.

Formatting follows the house spec:
  body 仿宋 12pt black, first-line indent 0.74cm, 1.5 line spacing, 6pt after
  headings 黑体: h1 16pt (centered, 24/18pt), h2 15pt (18/12), h3 14pt (14/8)
  tables 11pt, header row #E7E7E7 bold centered, single 0.5pt borders
  A4, margins 2.5/2.5/2/2 cm
"""
import io
import os
import re
import sys

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_ALIGN_VERTICAL, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

BLACK = RGBColor(0, 0, 0)
BODY_FONT = "仿宋"
HEAD_FONT = "黑体"
CODE_FONT = "Consolas"
ASCII_BODY = "Times New Roman"


def set_run_font(run, east, size=None, bold=False, ascii_font=None, color=BLACK):
    run.font.name = ascii_font or east
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    rfonts.set(qn("w:eastAsia"), east)
    rfonts.set(qn("w:ascii"), ascii_font or east)
    rfonts.set(qn("w:hAnsi"), ascii_font or east)
    if size:
        run.font.size = Pt(size)
    run.font.bold = bold
    if color is not None:
        run.font.color.rgb = color


def set_para(p, before=0, after=6, line=1.5, indent_first=0.0, indent_left=0.0,
             hanging=0.0, align=None):
    pf = p.paragraph_format
    pf.space_before = Pt(before)
    pf.space_after = Pt(after)
    pf.line_spacing = line
    pf.first_line_indent = Cm(indent_first) if indent_first else None
    pf.left_indent = Cm(indent_left) if indent_left else None
    if hanging:
        pf.first_line_indent = Cm(-hanging)
    if align is not None:
        p.alignment = align


def shade(element, fill):
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    element.append(shd)


def display_width(text):
    width = 0
    for ch in text:
        width += 2 if ord(ch) > 0x2E80 else 1
    return width


def add_row_flags(row, header=False):
    tr_pr = row._tr.get_or_add_trPr()
    cant = OxmlElement("w:cantSplit")
    tr_pr.append(cant)
    if header:
        head = OxmlElement("w:tblHeader")
        tr_pr.append(head)


def set_cell_borders(table):
    tbl = table._tbl
    tblPr = tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        el = OxmlElement(f"w:{edge}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), "4")
        el.set(qn("w:space"), "0")
        el.set(qn("w:color"), "000000")
        borders.append(el)
    tblPr.append(borders)


def add_field(paragraph, instr):
    run = paragraph.add_run()
    fld_begin = OxmlElement("w:fldChar")
    fld_begin.set(qn("w:fldCharType"), "begin")
    instr_el = OxmlElement("w:instrText")
    instr_el.set(qn("xml:space"), "preserve")
    instr_el.text = instr
    fld_sep = OxmlElement("w:fldChar")
    fld_sep.set(qn("w:fldCharType"), "separate")
    fld_end = OxmlElement("w:fldChar")
    fld_end.set(qn("w:fldCharType"), "end")
    run._r.append(fld_begin)
    run._r.append(instr_el)
    run._r.append(fld_sep)
    run._r.append(fld_end)
    set_run_font(run, BODY_FONT, 9, ascii_font=BODY_FONT)


INLINE = re.compile(r"(\*\*.+?\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\))")


def add_inline(paragraph, text):
    """Render simple inline markdown (bold, code, links) as runs."""
    pos = 0
    for m in INLINE.finditer(text):
        if m.start() > pos:
            run = paragraph.add_run(text[pos:m.start()])
            set_run_font(run, BODY_FONT, 12, ascii_font=ASCII_BODY)
        token = m.group(0)
        if token.startswith("**"):
            run = paragraph.add_run(token[2:-2])
            set_run_font(run, BODY_FONT, 12, bold=True, ascii_font=ASCII_BODY)
        elif token.startswith("`"):
            run = paragraph.add_run(token[1:-1])
            set_run_font(run, CODE_FONT, 10.5, ascii_font=CODE_FONT)
        else:
            label = re.match(r"\[([^\]]+)\]", token).group(1)
            url = re.search(r"\(([^)]+)\)", token).group(1)
            run = paragraph.add_run(label)
            set_run_font(run, BODY_FONT, 12, ascii_font=ASCII_BODY)
            run2 = paragraph.add_run(f"（{url}）")
            set_run_font(run2, BODY_FONT, 10, ascii_font=ASCII_BODY, color=RGBColor(0x40, 0x40, 0x40))
        pos = m.end()
    if pos < len(text):
        run = paragraph.add_run(text[pos:])
        set_run_font(run, BODY_FONT, 12, ascii_font=ASCII_BODY)


def clean_heading(text):
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return text.strip()


def add_heading(doc, text, level):
    text = clean_heading(text)
    size = {1: 16, 2: 15, 3: 14}.get(level, 12)
    before = {1: 24, 2: 18, 3: 14}.get(level, 12)
    after = {1: 18, 2: 12, 3: 8}.get(level, 6)
    p = doc.add_paragraph()
    p.style = doc.styles["Heading %d" % min(level, 3)]
    set_para(p, before=before, after=after, line=1.5,
             align=WD_ALIGN_PARAGRAPH.CENTER if level == 1 else WD_ALIGN_PARAGRAPH.LEFT)
    run = p.add_run(text)
    set_run_font(run, HEAD_FONT, size, bold=False, ascii_font=HEAD_FONT)
    return p


def add_paragraph(doc, text):
    p = doc.add_paragraph()
    set_para(p, indent_first=0.74)
    add_inline(p, text)
    return p


def add_list_item(doc, text, level=0, ordered=False, checkbox=False):
    p = doc.add_paragraph()
    set_para(p, after=3, indent_left=0.74 * (level + 1), hanging=0.74, line=1.5)
    if checkbox:
        prefix = "☐ "
    elif ordered:
        prefix = ""
    else:
        prefix = "• " if level == 0 else "◦ "
    run = p.add_run(prefix)
    set_run_font(run, BODY_FONT, 12, ascii_font=ASCII_BODY)
    add_inline(p, text)
    return p


def add_code_block(doc, lines):
    for i, line in enumerate(lines):
        p = doc.add_paragraph()
        set_para(p, before=0, after=0, line=1.0, indent_left=0.5)
        p.paragraph_format.space_after = Pt(0)
        run = p.add_run(line if line else " ")
        set_run_font(run, BODY_FONT, 9, ascii_font=CODE_FONT)
        shade(p._p.get_or_add_pPr(), "F2F2F2")
    # small gap after the block
    doc.paragraphs[-1].paragraph_format.space_after = Pt(6)


def parse_table(lines):
    rows = []
    for line in lines:
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        rows.append(cells)
    return rows


def add_table(doc, rows):
    if not rows:
        return
    ncol = max(len(r) for r in rows)
    table = doc.add_table(rows=len(rows), cols=ncol)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    set_cell_borders(table)
    # Content-proportional widths (total 17cm = usable portrait width): equal
    # widths wrap badly for mixed short/long columns.
    weights = []
    for j in range(ncol):
        w = max((display_width(r[j]) for r in rows if j < len(r)), default=8)
        weights.append(max(w, 8))
    total = sum(weights) or 1
    widths = [17.0 * w / total for w in weights]
    for i, row in enumerate(rows):
        add_row_flags(table.rows[i], header=(i == 0))
        for j in range(ncol):
            cell = table.cell(i, j)
            cell.width = Cm(widths[j])
            text = row[j] if j < len(row) else ""
            cell.text = ""
            p = cell.paragraphs[0]
            set_para(p, before=0, after=0, line=1.3, indent_first=0,
                     align=WD_ALIGN_PARAGRAPH.CENTER if i == 0 else WD_ALIGN_PARAGRAPH.LEFT)
            add_inline_cell(p, text, bold=(i == 0))
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER if i == 0 else WD_ALIGN_VERTICAL.TOP
            if i == 0:
                shade(cell._tc.get_or_add_tcPr(), "E7E7E7")
    # spacing paragraph after table
    p = doc.add_paragraph()
    set_para(p, before=0, after=6, line=1.0)
    return table


def add_inline_cell(paragraph, text, bold=False):
    pos = 0
    for m in INLINE.finditer(text):
        if m.start() > pos:
            run = paragraph.add_run(text[pos:m.start()])
            set_run_font(run, BODY_FONT, 11, bold=bold, ascii_font=ASCII_BODY)
        token = m.group(0)
        if token.startswith("**"):
            run = paragraph.add_run(token[2:-2])
            set_run_font(run, BODY_FONT, 11, bold=True, ascii_font=ASCII_BODY)
        elif token.startswith("`"):
            run = paragraph.add_run(token[1:-1])
            set_run_font(run, CODE_FONT, 10, ascii_font=CODE_FONT)
        else:
            label = re.match(r"\[([^\]]+)\]", token).group(1)
            run = paragraph.add_run(label)
            set_run_font(run, BODY_FONT, 11, bold=bold, ascii_font=ASCII_BODY)
        pos = m.end()
    if pos < len(text):
        run = paragraph.add_run(text[pos:])
        set_run_font(run, BODY_FONT, 11, bold=bold, ascii_font=ASCII_BODY)


def setup_document():
    doc = Document()
    sec = doc.sections[0]
    sec.page_width = Cm(21.0)
    sec.page_height = Cm(29.7)
    sec.top_margin = Cm(2.5)
    sec.bottom_margin = Cm(2.5)
    sec.left_margin = Cm(2.0)
    sec.right_margin = Cm(2.0)
    normal = doc.styles["Normal"]
    normal.font.name = ASCII_BODY
    normal.font.size = Pt(12)
    normal.font.color.rgb = BLACK
    rpr = normal.element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    rfonts.set(qn("w:eastAsia"), BODY_FONT)
    rfonts.set(qn("w:ascii"), ASCII_BODY)
    rfonts.set(qn("w:hAnsi"), ASCII_BODY)

    # header / footer (title page has none)
    sec.different_first_page_header_footer = True
    header = sec.header.paragraphs[0]
    header.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run = header.add_run("TamperGuard 用户手册  v0.2.2")
    set_run_font(run, BODY_FONT, 9, ascii_font=BODY_FONT)
    footer = sec.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = footer.add_run("第 ")
    set_run_font(run, BODY_FONT, 9, ascii_font=BODY_FONT)
    add_field(footer, "PAGE")
    run = footer.add_run(" 页")
    set_run_font(run, BODY_FONT, 9, ascii_font=BODY_FONT)
    return doc


def add_title_page(doc, title, subtitle):
    for _ in range(6):
        p = doc.add_paragraph()
        set_para(p, after=0, line=1.0)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(title)
    set_run_font(run, HEAD_FONT, 26, bold=False, ascii_font=HEAD_FONT)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(subtitle)
    set_run_font(run, BODY_FONT, 14, ascii_font=BODY_FONT)
    for _ in range(8):
        p = doc.add_paragraph()
        set_para(p, after=0, line=1.0)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("2026-11-26")
    set_run_font(run, BODY_FONT, 12, ascii_font=BODY_FONT)
    doc.add_page_break()


def main(md_path, out_path):
    with io.open(md_path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    doc = setup_document()
    add_title_page(doc, "TamperGuard 用户手册", "网页防篡改系统 · 版本 0.2.2")

    i = 0
    in_code = False
    code_lines = []
    table_lines = []
    in_table = False
    skip_first_h1 = True

    def flush_table():
        nonlocal table_lines, in_table
        if table_lines:
            rows = [r for r in parse_table(table_lines) if not all(re.fullmatch(r":?-{2,}:?", c or "") for c in r)]
            if rows:
                add_table(doc, rows)
        table_lines = []
        in_table = False

    while i < len(lines):
        line = lines[i].rstrip()

        if in_code:
            if line.strip().startswith("```"):
                in_code = False
                add_code_block(doc, code_lines)
                code_lines = []
            else:
                code_lines.append(line)
            i += 1
            continue

        if line.strip().startswith("```"):
            if in_table:
                flush_table()
            in_code = True
            i += 1
            continue

        if line.strip().startswith("|"):
            in_table = True
            table_lines.append(line)
            i += 1
            continue
        elif in_table:
            flush_table()

        if not line.strip():
            i += 1
            continue

        if line.startswith("# "):
            if skip_first_h1:
                skip_first_h1 = False
                i += 1
                continue
            add_heading(doc, line[2:].strip(), 1)
            i += 1
            continue
        if line.startswith("## "):
            add_heading(doc, line[3:].strip(), 1)
            i += 1
            continue
        if line.startswith("### "):
            add_heading(doc, line[4:].strip(), 2)
            i += 1
            continue
        if line.startswith("#### "):
            add_heading(doc, line[5:].strip(), 3)
            i += 1
            continue

        if line.strip() == "---":
            p = doc.add_paragraph()
            set_para(p, before=0, after=0, line=1.0)
            i += 1
            continue

        m = re.match(r"^(\s*)- \[( |x)\] (.+)$", line)
        if m:
            add_list_item(doc, m.group(3), level=len(m.group(1)) // 2, checkbox=True)
            i += 1
            continue
        m = re.match(r"^(\s*)- (.+)$", line)
        if m:
            add_list_item(doc, m.group(2), level=len(m.group(1)) // 2)
            i += 1
            continue
        m = re.match(r"^(\s*)(\d+)\. (.+)$", line)
        if m:
            p = doc.add_paragraph()
            level = len(m.group(1)) // 2
            set_para(p, after=3, indent_left=0.74 * (level + 1), hanging=0.74, line=1.5)
            run = p.add_run(f"{m.group(2)}. ")
            set_run_font(run, BODY_FONT, 12, ascii_font=ASCII_BODY)
            add_inline(p, m.group(3))
            i += 1
            continue

        if line.startswith("> "):
            p = doc.add_paragraph()
            set_para(p, indent_left=0.74, indent_first=0)
            run = p.add_run(line[2:])
            set_run_font(run, BODY_FONT, 10.5, ascii_font=ASCII_BODY)
            i += 1
            continue

        add_paragraph(doc, line.strip())
        i += 1

    if in_table:
        flush_table()
    if code_lines:
        add_code_block(doc, code_lines)

    doc.save(out_path)
    print("saved", out_path, "paragraphs=", len(doc.paragraphs), "tables=", len(doc.tables))


if __name__ == "__main__":
    md = sys.argv[1] if len(sys.argv) > 1 else "docs/user-manual.md"
    out = sys.argv[2] if len(sys.argv) > 2 else "docs/TamperGuard用户手册_v0.2.2.docx"
    main(md, out)
