"""v2.0.0 — génération des PDFs conformité (réquisition, registre RGPD…).

Utilise ReportLab (pure Python, pas de dépendance GTK/Cairo). Charge la police
DejaVuSans si disponible pour le support Unicode (accents FR propres), sinon
fallback Helvetica (qui gère mal les accents).

Toutes les fonctions `render_*` écrivent dans le `path` fourni (BytesIO ou
chemin disque) et retournent le nombre d'octets écrits.
"""
from __future__ import annotations

import io
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether,
)

log = logging.getLogger("syslog-server")

_FONT_DIR = Path("/opt/syslog-server/static/fonts")
_FONT_REGISTERED = False


def _register_unicode_font():
    """Enregistre DejaVuSans si on en trouve une copie. Les distributions
    Debian/Ubuntu ont typiquement le fichier dans /usr/share/fonts/..."""
    global _FONT_REGISTERED
    if _FONT_REGISTERED:
        return

    candidates = [
        _FONT_DIR / "DejaVuSans.ttf",
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/usr/share/fonts/TTF/DejaVuSans.ttf"),
        Path("/usr/share/fonts/dejavu/DejaVuSans.ttf"),
    ]
    bold_candidates = [
        _FONT_DIR / "DejaVuSans-Bold.ttf",
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        Path("/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"),
    ]
    reg = next((p for p in candidates if p.exists()), None)
    bold = next((p for p in bold_candidates if p.exists()), None)
    if reg:
        try:
            pdfmetrics.registerFont(TTFont("DejaVuSans", str(reg)))
            if bold:
                pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", str(bold)))
            _FONT_REGISTERED = True
        except Exception as e:
            log.warning(f"PDF: registerFont failed ({reg}): {e}")


def _styles() -> dict:
    _register_unicode_font()
    base = getSampleStyleSheet()
    font = "DejaVuSans" if _FONT_REGISTERED else "Helvetica"
    bold = "DejaVuSans-Bold" if _FONT_REGISTERED else "Helvetica-Bold"

    return {
        "title":    ParagraphStyle("Title", parent=base["Title"], fontName=bold, fontSize=18, spaceAfter=10, leading=22),
        "h2":       ParagraphStyle("H2", parent=base["Heading2"], fontName=bold, fontSize=13, spaceBefore=14, spaceAfter=6),
        "normal":   ParagraphStyle("Normal", parent=base["Normal"], fontName=font, fontSize=10, leading=14),
        "small":    ParagraphStyle("Small", parent=base["Normal"], fontName=font, fontSize=8.5, leading=11, textColor=colors.HexColor("#555")),
        "mono":     ParagraphStyle("Mono", parent=base["Normal"], fontName="Courier", fontSize=8.5, leading=11),
        "table_h":  ParagraphStyle("TH", fontName=bold, fontSize=9, leading=12, textColor=colors.white),
        "table_c":  ParagraphStyle("TC", fontName=font, fontSize=9, leading=12),
    }


def _footer(canvas, doc):
    canvas.saveState()
    font = "DejaVuSans" if _FONT_REGISTERED else "Helvetica"
    canvas.setFont(font, 8)
    canvas.setFillColor(colors.HexColor("#888"))
    txt = f"SyslogHub v2.0 — page {canvas.getPageNumber()}"
    canvas.drawRightString(A4[0] - 15*mm, 10*mm, txt)
    canvas.restoreState()


def render_requisition_pv(
    out_path: str | io.BytesIO,
    *,
    requisition: dict,
    organization: dict,
    chain_entries: list[dict],
    operator_username: str,
) -> None:
    """Génère le PV d'extraction pour une réquisition judiciaire.

    `requisition` : dict with number, opj_name, opj_service, opj_email, justification,
        space_id, space_name, time_from, time_to, created_at.
    `organization` : dict with name, address, siren, dpo_name, dpo_email.
    `chain_entries` : liste de {day, manifest_sha256, tsa_status, tsa_gen_time,
        tsa_serial, tsa_url, files_count, total_bytes}."""
    S = _styles()
    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=18*mm, bottomMargin=18*mm,
        title=f"PV réquisition {requisition['number']}",
        author=organization.get("name") or "SyslogHub",
    )
    story = []

    # Header
    org_name = organization.get("name") or "Organisation non renseignée"
    story.append(Paragraph(f"<b>{_esc(org_name)}</b>", S["normal"]))
    if organization.get("address"):
        story.append(Paragraph(_esc(organization["address"]), S["small"]))
    if organization.get("siren"):
        story.append(Paragraph(f"SIREN : {_esc(organization['siren'])}", S["small"]))
    story.append(Spacer(1, 8))

    # Title
    story.append(Paragraph("Procès-verbal d'extraction", S["title"]))
    story.append(Paragraph(
        f"Réquisition n° <b>{_esc(requisition['number'])}</b>",
        S["normal"]
    ))
    story.append(Paragraph(
        f"Généré le {_esc(_now_fr())} par <b>{_esc(operator_username)}</b>",
        S["small"]
    ))
    story.append(Spacer(1, 10))

    # Requirement context
    story.append(Paragraph("Requérant (Officier de Police Judiciaire)", S["h2"]))
    opj_table = [
        ["Nom",     requisition.get("opj_name") or "—"],
        ["Service", requisition.get("opj_service") or "—"],
        ["Email",   requisition.get("opj_email") or "—"],
    ]
    story.append(_kv_table(opj_table, S))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Justification de la réquisition", S["h2"]))
    story.append(Paragraph(_esc(requisition.get("justification") or "—"), S["normal"]))
    story.append(Spacer(1, 10))

    # Scope
    story.append(Paragraph("Périmètre de l'extraction", S["h2"]))
    perim = [
        ["Espace",             requisition.get("space_name") or "Tous les espaces"],
        ["Début de la plage",  requisition.get("time_from")],
        ["Fin de la plage",    requisition.get("time_to")],
        ["Créée le",           requisition.get("created_at")],
    ]
    story.append(_kv_table(perim, S))
    story.append(Spacer(1, 10))

    # Integrity table
    story.append(Paragraph("Intégrité cryptographique des jours couverts", S["h2"]))
    if chain_entries:
        head = ["Jour", "Fichiers", "Taille", "Manifest SHA-256 (12 premiers hex)", "TSA", "Horodatage"]
        data = [head]
        for e in chain_entries:
            data.append([
                e.get("day", "—"),
                str(e.get("files_count", "—")),
                _fmt_bytes(e.get("total_bytes", 0)),
                (e.get("manifest_sha256") or "")[:12] + "…",
                e.get("tsa_status", "—"),
                e.get("tsa_gen_time") or "—",
            ])
        tbl = Table(data, colWidths=[22*mm, 18*mm, 22*mm, 60*mm, 20*mm, 30*mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
            ("FONTNAME",   (0,0), (-1,0), "DejaVuSans-Bold" if _FONT_REGISTERED else "Helvetica-Bold"),
            ("FONTNAME",   (0,1), (-1,-1), "DejaVuSans" if _FONT_REGISTERED else "Helvetica"),
            ("FONTSIZE",   (0,0), (-1,-1), 8.5),
            ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
            ("GRID",       (0,0), (-1,-1), 0.25, colors.HexColor("#ccc")),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f9fafb")]),
        ]))
        story.append(tbl)
    else:
        story.append(Paragraph("<i>Aucune entrée de chaîne d'intégrité pour la plage demandée.</i>", S["small"]))
    story.append(Spacer(1, 12))

    # Legal mentions
    story.append(Paragraph("Cadre légal", S["h2"]))
    legal = (
        "Cette extraction est produite en application de la "
        "<b>loi n° 2004-575 du 21 juin 2004 pour la confiance dans l'économie numérique (LCEN)</b>, "
        "article 6-II, qui impose aux opérateurs de services de communication au public en ligne "
        "la conservation des données de connexion pendant une durée d'un an à compter de leur création "
        "(cf. art. R. 10-13 du Code des postes et des communications électroniques). "
        "Le <b>Règlement (UE) 2016/679 (RGPD)</b>, article 5-1-e, impose par ailleurs que ces données "
        "soient conservées sous une forme permettant l'identification des personnes concernées pendant "
        "une durée n'excédant pas celle nécessaire au regard des finalités poursuivies."
    )
    story.append(Paragraph(legal, S["normal"]))
    story.append(Spacer(1, 8))

    mention = (
        "Les fichiers de logs extraits ainsi que leurs hashs cryptographiques et les horodatages "
        "qualifiés RFC 3161 sont fournis dans le bundle ZIP joint. "
        "Un script <i>verify.sh</i> permet une vérification indépendante de l'intégrité du bundle "
        "en dehors de SyslogHub (dépendances : bash, sha256sum, openssl)."
    )
    story.append(Paragraph(mention, S["normal"]))
    story.append(Spacer(1, 10))

    # Signature / contact
    story.append(Paragraph("Contact conformité", S["h2"]))
    dpo = [
        ["Responsable du traitement", organization.get("name") or "—"],
        ["DPO",                       organization.get("dpo_name") or "Non désigné"],
        ["Contact DPO",               organization.get("dpo_email") or "—"],
        ["Opérateur d'extraction",    operator_username],
    ]
    story.append(_kv_table(dpo, S))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)


def render_gdpr_register(
    out_path: str | io.BytesIO,
    *,
    organization: dict,
    spaces: list[dict],
) -> None:
    """Registre des traitements art. 30 RGPD — un encart par space actif."""
    S = _styles()
    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=18*mm, bottomMargin=18*mm,
        title="Registre de traitement art. 30 RGPD",
    )
    story = []
    story.append(Paragraph(_esc(organization.get("name") or "—"), S["normal"]))
    if organization.get("address"):
        story.append(Paragraph(_esc(organization["address"]), S["small"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Registre des activités de traitement", S["title"]))
    story.append(Paragraph("Article 30 du Règlement (UE) 2016/679 (RGPD)", S["normal"]))
    story.append(Paragraph(f"Généré le {_now_fr()}", S["small"]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Responsable du traitement", S["h2"]))
    rt = [
        ["Organisation",         organization.get("name") or "—"],
        ["Adresse",              organization.get("address") or "—"],
        ["SIREN",                organization.get("siren") or "—"],
        ["DPO",                  organization.get("dpo_name") or "Non désigné"],
        ["Contact DPO",          organization.get("dpo_email") or "—"],
        ["Contact droit d'accès",organization.get("privacy_contact_email") or "—"],
    ]
    story.append(_kv_table(rt, S))
    story.append(Spacer(1, 14))

    if not spaces:
        story.append(Paragraph("<i>Aucun traitement configuré.</i>", S["small"]))
    for sp in spaces:
        story.append(Paragraph(f"Traitement : journalisation syslog — {_esc(sp['name'])}", S["h2"]))
        data = [
            ["Finalité",             "Conservation des données de connexion WiFi public (LCEN art. 6-II)."],
            ["Base légale",          "Obligation légale (RGPD art. 6-1-c) — LCEN art. 6-II + art. R.10-13 CPCE."],
            ["Catégories de données","Adresse IP source, horodatage, ports, identifiant équipement émetteur ; "
                                     "si parsing DHCP actif : adresse MAC et nom d'hôte ; si sync Omada : identifiant hotspot."],
            ["Catégories de personnes","Utilisateurs finaux du WiFi public, administrateurs réseau."],
            ["Destinataires",        "Personnel interne habilité (RBAC SyslogHub) ; Officier de Police Judiciaire sur réquisition."],
            ["Transferts hors UE",   "Aucun."],
            ["Durée de conservation", f"{sp.get('retention_days', 365)} jours (purge automatique)."],
            ["Mesures de sécurité",  "Chiffrement au repos Fernet (secrets) ; hash chaîné SHA-256 + horodatage RFC3161 ; "
                                     "contrôle d'accès multi-utilisateurs (RBAC) ; journal d'audit ; backup chiffré."],
        ]
        story.append(_kv_table(data, S, label_w=48*mm))
        story.append(Spacer(1, 10))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)


def render_portal_notice(
    out_path: str | io.BytesIO,
    *,
    organization: dict,
    space: dict,
) -> None:
    """Mention d'information à afficher sur le captive portal."""
    S = _styles()
    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=18*mm, bottomMargin=18*mm,
        title="Information RGPD — captive portal",
    )
    story = []
    org = organization.get("name") or "—"
    story.append(Paragraph("Information sur vos données de connexion", S["title"]))
    story.append(Paragraph(
        f"Le WiFi <b>{_esc(space.get('name', ''))}</b> est fourni par <b>{_esc(org)}</b>.",
        S["normal"]
    ))
    story.append(Spacer(1, 10))

    sections = [
        ("Finalité",
         "Conservation des données de connexion conformément à la "
         "loi pour la confiance dans l'économie numérique (LCEN, art. 6-II), "
         "pour répondre aux réquisitions judiciaires le cas échéant."),
        ("Données collectées",
         "Adresse IP attribuée, horodatage de connexion et déconnexion, identifiant "
         "matériel (adresse MAC), identifiant utilisé lors de l'authentification au "
         "captive portal (email, numéro SMS, ou code)."),
        ("Base légale",
         "Obligation légale (RGPD art. 6-1-c)."),
        ("Durée de conservation",
         f"{space.get('retention_days', 365)} jours à compter de la connexion, "
         "puis suppression automatique."),
        ("Destinataires",
         "Personnel technique de l'organisation (en accès restreint) ; autorité judiciaire "
         "sur réquisition formelle."),
        ("Vos droits",
         "Conformément au RGPD, vous disposez d'un droit d'accès, de rectification et "
         "de limitation. Certains droits (effacement, portabilité) sont limités par "
         "l'obligation légale de conservation."),
        ("Contact",
         organization.get("privacy_contact_email")
         or organization.get("dpo_email")
         or "Contactez l'accueil de l'établissement."),
    ]
    for title, body in sections:
        story.append(Paragraph(title, S["h2"]))
        story.append(Paragraph(_esc(body), S["normal"]))
        story.append(Spacer(1, 4))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)


def render_portal_notice_markdown(organization: dict, space: dict) -> str:
    """Variante markdown pour intégration directe dans le portail."""
    org = organization.get("name") or ""
    return (
        f"# Information sur vos données de connexion\n\n"
        f"Le WiFi **{space.get('name', '')}** est fourni par **{org}**.\n\n"
        f"## Finalité\n"
        f"Conservation des données de connexion conformément à la loi pour la confiance "
        f"dans l'économie numérique (LCEN, art. 6-II).\n\n"
        f"## Données collectées\n"
        f"Adresse IP attribuée, horodatage de connexion et déconnexion, adresse MAC, "
        f"identifiant d'authentification (email/SMS/code).\n\n"
        f"## Base légale\n"
        f"Obligation légale — RGPD art. 6-1-c.\n\n"
        f"## Durée de conservation\n"
        f"{space.get('retention_days', 365)} jours, puis suppression automatique.\n\n"
        f"## Vos droits\n"
        f"Droit d'accès, de rectification et de limitation. Les droits d'effacement et "
        f"de portabilité sont limités par l'obligation légale de conservation.\n\n"
        f"## Contact\n"
        f"{organization.get('privacy_contact_email') or organization.get('dpo_email') or 'Accueil de l établissement.'}\n"
    )


def render_annual_report(
    out_path: str | io.BytesIO,
    *,
    organization: dict,
    year: int,
    per_space: list[dict],
    totals: dict,
) -> None:
    """Rapport annuel de conformité.

    `per_space` : [{name, uptime_pct, gaps, requisitions_count, tsa_ok, tsa_failed,
        volume_bytes}, ...]
    `totals`    : {requisitions_total, tsa_success_rate_pct}
    """
    S = _styles()
    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=18*mm, bottomMargin=18*mm,
        title=f"Rapport annuel de conformité {year}",
    )
    story = []
    story.append(Paragraph(_esc(organization.get("name") or "—"), S["normal"]))
    story.append(Paragraph(f"Rapport annuel de conformité {year}", S["title"]))
    story.append(Paragraph(f"Généré le {_now_fr()}", S["small"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Indicateurs consolidés", S["h2"]))
    story.append(_kv_table([
        ["Réquisitions honorées",    str(totals.get("requisitions_total", 0))],
        ["Horodatages TSA réussis",  f"{totals.get('tsa_success_rate_pct', 0):.1f} %"],
        ["Nombre d'espaces actifs",  str(len(per_space))],
    ], S))
    story.append(Spacer(1, 10))

    for sp in per_space:
        story.append(Paragraph(f"Espace : {_esc(sp['name'])}", S["h2"]))
        story.append(_kv_table([
            ["Uptime collecte",              f"{sp.get('uptime_pct', 0):.1f} %"],
            ["Gaps détectés (jours sans log)",str(sp.get('gaps', 0))],
            ["Réquisitions",                 str(sp.get("requisitions_count", 0))],
            ["TSA — ok / échecs",             f"{sp.get('tsa_ok', 0)} / {sp.get('tsa_failed', 0)}"],
            ["Volume conservé",              _fmt_bytes(sp.get("volume_bytes", 0))],
        ], S))
        story.append(Spacer(1, 8))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)


# ── helpers ──────────────────────────────────────────────────────────────────

def _esc(s):
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _kv_table(rows, styles, label_w=38*mm):
    data = [[Paragraph(f"<b>{_esc(r[0])}</b>", styles["table_c"]),
             Paragraph(_esc(r[1] or "—"), styles["table_c"])] for r in rows]
    tbl = Table(data, colWidths=[label_w, None])
    tbl.setStyle(TableStyle([
        ("VALIGN",     (0,0), (-1,-1), "TOP"),
        ("BACKGROUND", (0,0), (0,-1),  colors.HexColor("#f3f4f6")),
        ("GRID",       (0,0), (-1,-1), 0.25, colors.HexColor("#ddd")),
        ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING",   (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0), (-1,-1), 4),
    ]))
    return tbl


def _fmt_bytes(n: int) -> str:
    if n is None:
        return "—"
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


def _now_fr() -> str:
    return datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
