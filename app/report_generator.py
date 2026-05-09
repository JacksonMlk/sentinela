"""
Assessment DOCX Report Generator — profissional.
Generates professional AWS Assessment document following the Wibx template structure:
  Escopo → Cenário Atual (por camada) → Melhorias → Landing Zone →
  Considerações Gerais → Pain Points → Oportunidades → Referências
"""
import io
import logging
from datetime import datetime
from docx import Document
from docx.shared import Pt, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# COLOR PALETTE
# ---------------------------------------------------------------------------
PINK       = RGBColor(0xFF, 0x67, 0x9A)   # section titles (pink headings)
NAVY       = RGBColor(0x0B, 0x19, 0x56)   # subsection titles / labels
GREEN      = RGBColor(0x18, 0x80, 0x38)   # resource IDs / positive values
DARK_GRAY  = RGBColor(0x33, 0x33, 0x33)   # body text
LIGHT_GRAY = RGBColor(0x99, 0x99, 0x99)   # footers / secondary
RED        = RGBColor(0xDC, 0x26, 0x26)   # critical severity
ORANGE     = RGBColor(0xEA, 0x58, 0x0C)   # high severity
AMBER      = RGBColor(0xD9, 0x77, 0x06)   # medium / warning
BLUE       = RGBColor(0x1D, 0x4E, 0xD8)   # low severity / links


# ---------------------------------------------------------------------------
# FORMATTING HELPERS
# ---------------------------------------------------------------------------

def _font(run, name="Calibri", size=11, bold=False, italic=False, color=None):
    run.font.name = name
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    if color:
        run.font.color.rgb = color


def _heading(doc, text, level=1, color=NAVY):
    """Pink for level-1 section titles, Navy for subsections."""
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(18 if level == 1 else 10)
    p.paragraph_format.space_after  = Pt(6)
    run = p.add_run(text)
    _font(run, size={1: 18, 2: 14, 3: 12}.get(level, 11), bold=True, color=color)
    return p


def _body(doc, text, size=11, color=DARK_GRAY, indent_cm=0):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(6)
    if indent_cm:
        p.paragraph_format.left_indent = Cm(indent_cm)
    run = p.add_run(text)
    _font(run, size=size, color=color)
    return p


def _bullet(doc, text, size=10.5, color=DARK_GRAY, indent_cm=0):
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.space_after = Pt(4)
    if indent_cm:
        p.paragraph_format.left_indent = Cm(indent_cm)
    run = p.add_run(text)
    _font(run, size=size, color=color)
    return p


def _kv(doc, key, value, key_color=NAVY, val_color=DARK_GRAY):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(4)
    r1 = p.add_run(f"{key}: ")
    _font(r1, bold=True, color=key_color)
    r2 = p.add_run(str(value) if value is not None else "N/A")
    _font(r2, color=val_color)
    return p


def _aws_id(doc, text):
    """Resource ID in monospace green, indented."""
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Cm(1)
    p.paragraph_format.space_after = Pt(3)
    run = p.add_run(text)
    _font(run, name="Courier New", size=9.5, color=GREEN)
    return p


def _layer_section(doc, layer_data: dict | None, level: int = 2):
    """
    Render a service-layer block from the narrative JSON.
    layer_data = {"titulo": "...", "bullets": ["...", ...]}
    """
    if not layer_data or not isinstance(layer_data, dict):
        return
    titulo  = layer_data.get("titulo", "")
    bullets = layer_data.get("bullets") or []
    if titulo:
        _heading(doc, titulo, level=level, color=NAVY)
    for b in bullets:
        _bullet(doc, str(b))


def _conta_section(doc, conta: dict):
    """Render a single Landing Zone account block."""
    nome     = conta.get("nome", "")
    funcao   = conta.get("funcao_principal", "")
    recursos = conta.get("recursos_comuns") or []
    beneficio = conta.get("beneficio", "")

    _heading(doc, nome, level=3, color=NAVY)
    if funcao:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(4)
        r1 = p.add_run("Função Principal: ")
        _font(r1, bold=True, color=NAVY)
        r2 = p.add_run(funcao)
        _font(r2)

    if recursos:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(4)
        r = p.add_run("Recursos Comuns:")
        _font(r, bold=True, color=NAVY)
        for rec in recursos:
            _bullet(doc, str(rec), indent_cm=0.5)

    if beneficio:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(6)
        r1 = p.add_run("Benefício: ")
        _font(r1, bold=True, color=NAVY)
        r2 = p.add_run(beneficio)
        _font(r2, italic=True)


# ---------------------------------------------------------------------------
# MAIN GENERATOR
# ---------------------------------------------------------------------------

def generate_assessment_docx(report, client) -> io.BytesIO:
    """
    Generate a professional AWS Assessment DOCX following the profissional structure.
    Calls Gemini to generate Wibx-style narrative, then renders the DOCX.
    Returns a BytesIO buffer ready to stream as a download.
    """
    # ── 1. call AI for Wibx-style narrative ──────────────────────────────
    narrative: dict = {}
    try:
        from app.claude_analyzer import generate_assessment_narrative
        finops_analysis = report.rightsizing_recommendations or {}
        narrative = generate_assessment_narrative(
            raw_data=report.raw_data or {},
            finops_analysis=finops_analysis,
        )
        logger.info("Assessment narrative generated successfully.")
    except Exception as exc:
        logger.warning(f"Narrative generation failed: {exc}. Building report from raw data only.")

    # ── 2. unpack report fields ───────────────────────────────────────────
    raw        = report.raw_data or {}
    finops     = report.rightsizing_recommendations or {}
    iam        = report.iam_findings or {}
    s3_data    = report.s3_findings or {}
    network    = report.network_findings or {}
    encryption = report.encryption_findings or {}
    compliance = report.compliance_findings or {}
    unused     = report.unused_resources or {}
    ri_recs    = report.ri_recommendations or {}

    analysis_date  = (report.completed_at or report.started_at or datetime.utcnow()).strftime("%d/%m/%Y")
    regions        = client.aws_regions or "us-east-1"
    monthly_cost   = report.monthly_cost or 0.0
    savings_total  = report.potential_savings or 0.0

    s3_costs_raw  = s3_data.get("costs", {})
    s3_sec_raw    = s3_data.get("security", {})
    s3_buckets    = s3_costs_raw.get("buckets", [])
    public_bkts   = s3_sec_raw.get("public_buckets", [])
    unenc_bkts    = s3_sec_raw.get("unencrypted_buckets", [])
    no_lifecycle  = sum(1 for b in s3_buckets if not b.get("has_lifecycle"))
    no_mfa        = iam.get("users_without_mfa", [])
    old_keys      = iam.get("users_with_old_keys", [])
    inactive_iam  = iam.get("inactive_users", [])
    open_sgs      = network.get("open_security_groups", [])
    vpcs_no_flow  = network.get("vpcs_without_flow_logs", [])
    no_guardduty  = network.get("regions_without_guardduty", [])
    enc_ebs       = encryption.get("unencrypted_ebs", [])
    unattached    = unused.get("unattached_volumes", [])
    unused_eips   = unused.get("unused_eips", [])
    old_snaps     = unused.get("old_snapshots", [])
    idle_lbs      = unused.get("idle_load_balancers", [])
    stopped_ec2   = unused.get("stopped_instances", [])
    sh_findings   = compliance.get("security_hub", [])
    sp_recs       = ri_recs.get("savings_plans", [])
    ri_list       = ri_recs.get("reserved_instances", [])
    cost_by_svc   = report.cost_by_service or []
    rightsizing   = raw.get("rightsizing", {}).get("ec2", [])
    monthly_totals = raw.get("cost_and_usage", {}).get("monthly_totals", [])

    # ── shorthand narrative sections (safe .get on None) ─────────────────
    def _n(key: str):
        return narrative.get(key) or {}

    cenario    = _n("cenario_atual")
    camadas    = _n("camadas")
    melhorias  = _n("melhorias")
    lz         = _n("landing_zone")
    outros_svc = narrative.get("outros_servicos") or []
    consider   = _n("consideracoes")
    pain_pts   = narrative.get("pain_points") or []
    opps       = narrative.get("oportunidades") or []

    # ── 3. build the DOCX ─────────────────────────────────────────────────
    doc = Document()
    section = doc.sections[0]
    section.page_height   = Cm(29.7)
    section.page_width    = Cm(21.0)
    section.left_margin   = Cm(2.5)
    section.right_margin  = Cm(2.5)
    section.top_margin    = Cm(2.5)
    section.bottom_margin = Cm(2.5)
    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(11)

    # ═════════════════════════════════════════════════════════════════════
    # CAPA
    # ═════════════════════════════════════════════════════════════════════
    for _ in range(4):
        doc.add_paragraph()

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run("Assessment Report")
    _font(r, size=28, bold=True, color=PINK)

    doc.add_paragraph()

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(f"Arquitetura Cloud — {client.company}")
    _font(r, size=18, bold=True, color=NAVY)

    doc.add_paragraph()
    doc.add_paragraph()

    for label, value in [
        ("Versão:", "01"),
        ("Responsável Técnico:", "Sentinela"),
        ("Data:", analysis_date),
    ]:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r1 = p.add_run(f"{label} ")
        _font(r1, size=12, color=LIGHT_GRAY)
        r2 = p.add_run(value)
        _font(r2, size=12, bold=True, color=NAVY)

    if client.aws_account_id:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(f"Conta AWS: {client.aws_account_id}")
        _font(r, name="Courier New", size=11, color=GREEN)

    doc.add_page_break()

    # ═════════════════════════════════════════════════════════════════════
    # SUMÁRIO  (dynamic — only lists sections that will actually be rendered)
    # ═════════════════════════════════════════════════════════════════════
    _heading(doc, "Sumário", level=1, color=PINK)

    toc_entries: list[tuple[str, str]] = [
        ("Escopo", ""),
        ("Cenário Atual", ""),
    ]
    # Cenário Atual sub-entries
    if camadas.get("computacao"):
        toc_entries.append(("", camadas["computacao"].get("titulo", "Camada de Computação")))
    if camadas.get("seguranca_hub"):
        toc_entries.append(("", camadas["seguranca_hub"].get("titulo", "Camada de Segurança – Security Hub")))
    if camadas.get("seguranca_guardduty"):
        toc_entries.append(("", camadas["seguranca_guardduty"].get("titulo", "Camada de Segurança - GuardDuty")))
    if camadas.get("rede"):
        toc_entries.append(("", camadas["rede"].get("titulo", "Camada de Rede – VPC")))
    if camadas.get("iam"):
        toc_entries.append(("", camadas["iam"].get("titulo", "IAM (Usuários e Grupos)")))
    if camadas.get("ebs"):
        toc_entries.append(("", camadas["ebs"].get("titulo", "EBS")))
    if camadas.get("savings_plans"):
        toc_entries.append(("", camadas["savings_plans"].get("titulo", "Savings Plans")))
    if camadas.get("s3"):
        toc_entries.append(("", camadas["s3"].get("titulo", "S3")))

    # Top-level sections
    has_melhorias = any(melhorias.get(k) for k in ("computacao", "rede", "iam", "ebs", "s3"))
    if has_melhorias:
        toc_entries.append(("Melhorias", ""))
    toc_entries.append(("Recomendações de Serviços", ""))
    toc_entries.append(("Considerações Gerais", ""))
    if pain_pts:
        toc_entries.append(("Pain Points", ""))
    if opps:
        toc_entries.append(("Oportunidades", ""))
    toc_entries.append(("Referências", ""))

    for main, sub in toc_entries:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(4)
        if main:
            r = p.add_run(main)
            _font(r, bold=True, color=NAVY)
        else:
            p.paragraph_format.left_indent = Cm(1.5)
            r = p.add_run(sub)
            _font(r, color=DARK_GRAY)

    doc.add_page_break()

    # ═════════════════════════════════════════════════════════════════════
    # ESCOPO
    # ═════════════════════════════════════════════════════════════════════
    _heading(doc, "Escopo", level=1, color=PINK)
    _body(doc, (
        f"O presente relatório visa a avaliação e identificação de possíveis melhorias "
        f"de segurança e boas práticas no ambiente AWS utilizado por {client.company}. "
        f"Ao longo do documento, serão apresentadas as recomendações necessárias e sugestões "
        f"de novos serviços, com suas respectivas finalidades, que podem ser implementadas."
    ))
    doc.add_paragraph()
    _body(doc, (
        "Este trabalho é baseado no AWS Well-Architected Framework, publicamente reconhecido "
        "como o conjunto das melhores práticas para a implementação de aplicações em nuvem."
    ))

    doc.add_page_break()

    # ═════════════════════════════════════════════════════════════════════
    # CENÁRIO ATUAL
    # ═════════════════════════════════════════════════════════════════════
    _heading(doc, "Cenário Atual", level=1, color=PINK)

    # Intro paragraph from narrative
    intro_text = cenario.get("intro", "")
    if intro_text:
        _body(doc, intro_text)
    else:
        # fallback: build from raw data
        acct = client.aws_account_id or raw.get("account_id", "N/A")
        _body(doc, (
            f"Realizamos o levantamento técnico da conta {acct}, onde {client.company} opera "
            f"sua infraestrutura AWS. Foram coletados dados de segurança, custo e conformidade "
            f"nas regiões: {regions}."
        ))

    # Critical vulnerabilities callout
    criticas = cenario.get("vulnerabilidades_criticas") or []
    if criticas:
        doc.add_paragraph()
        p = doc.add_paragraph()
        r = p.add_run("Vulnerabilidades Críticas Identificadas:")
        _font(r, bold=True, color=RED)
        for vuln in criticas:
            _bullet(doc, str(vuln), color=RED)

    # Arquitetura subsection
    _heading(doc, "Arquitetura", level=2, color=NAVY)
    arch_text = cenario.get("arquitetura", "")
    if arch_text:
        _body(doc, arch_text)

    # ── service-layer sections (only rendered when narrative has data) ──
    for key in ("computacao", "seguranca_hub", "seguranca_guardduty",
                "rede", "iam", "ebs", "savings_plans", "s3"):
        _layer_section(doc, camadas.get(key), level=2)

    # ── fallback: raw-data blocks if narrative was empty ─────────────────
    if not any(camadas.get(k) for k in camadas):
        _heading(doc, "IAM (Usuários e Grupos)", level=2)
        root_mfa = iam.get("root_mfa_enabled")
        if root_mfa is False:
            _bullet(doc, "MFA da conta root NÃO está habilitado — risco crítico.", color=RED)
        _bullet(doc, f"Usuários sem MFA: {len(no_mfa)}")
        _bullet(doc, f"Usuários com chaves de acesso antigas (>90 dias): {len(old_keys)}")
        _bullet(doc, f"Usuários IAM inativos: {len(inactive_iam)}")
        _bullet(doc, f"Políticas com permissões excessivas: {len(iam.get('overprivileged_policies', []))}")

        _heading(doc, "Camada de Rede – VPC", level=2)
        _bullet(doc, f"Security Groups com portas abertas para 0.0.0.0/0: {len(open_sgs)}")
        _bullet(doc, f"VPCs sem VPC Flow Logs: {len(vpcs_no_flow)}")
        _bullet(doc, f"Regiões sem GuardDuty habilitado: {len(no_guardduty)}")

        _heading(doc, "S3", level=2)
        _bullet(doc, f"Total de buckets: {len(s3_buckets)} — {s3_costs_raw.get('total_size_gb', 0):.1f} GB")
        _bullet(doc, f"Buckets sem Lifecycle Policy: {no_lifecycle}")
        if public_bkts:
            _bullet(doc, f"Buckets com acesso público: {len(public_bkts)}", color=RED)

        _heading(doc, "EBS", level=2)
        _bullet(doc, f"Volumes EBS não anexados: {len(unattached)}")
        _bullet(doc, f"Volumes EBS sem criptografia: {len(enc_ebs)}")

        if sp_recs or ri_list:
            _heading(doc, "Savings Plans", level=2)
            if sp_recs:
                _bullet(doc, f"Recomendações de Savings Plans disponíveis: {len(sp_recs)}")
            if ri_list:
                _bullet(doc, f"Recomendações de Reserved Instances: {len(ri_list)}")

    doc.add_page_break()

    # ═════════════════════════════════════════════════════════════════════
    # MELHORIAS
    # ═════════════════════════════════════════════════════════════════════
    if has_melhorias:
        _heading(doc, "Melhorias", level=1, color=PINK)

        for key in ("computacao", "rede", "iam", "ebs", "s3"):
            mel = melhorias.get(key)
            if mel and isinstance(mel, dict):
                titulo  = mel.get("titulo", "")
                bullets = mel.get("bullets") or []
                if titulo:
                    _heading(doc, titulo, level=2, color=NAVY)
                for b in bullets:
                    _bullet(doc, str(b))

        doc.add_page_break()

    # ═════════════════════════════════════════════════════════════════════
    # RECOMENDAÇÕES DE SERVIÇOS
    # ═════════════════════════════════════════════════════════════════════
    _heading(doc, "Recomendações de Serviços", level=1, color=PINK)
    _body(doc, (
        "Nesta seção, listamos alguns serviços que poderão ser utilizados futuramente "
        f"no ambiente de {client.company}. O objetivo é apresentar novas soluções que "
        "contribuam para a estabilidade e segurança do ambiente."
    ))

    # Landing Zone
    usar_org   = lz.get("usar_organizations", False)
    lz_contas  = lz.get("contas") or []
    lz_optim   = lz.get("otimizacao_governanca") or []

    _heading(doc, "Proposta de Estrutura das Contas e Landing Zone", level=2, color=NAVY)

    if not usar_org and lz_contas:
        for conta in lz_contas:
            _conta_section(doc, conta)
    elif usar_org and lz_optim:
        _heading(doc, "Otimização da Governança Multi-Conta", level=3, color=NAVY)
        for item in lz_optim:
            _bullet(doc, str(item))
    else:
        # generic fallback landing zone
        _body(doc, (
            "Recomenda-se a implementação de AWS Organizations com Landing Zones para "
            "segregar os ambientes em contas distintas: Management, Network, Development e Production."
        ))
        for nome, funcao, beneficio in [
            ("Conta Management (Gerenciamento)",
             "Centralizar e gerenciar todas as contas da AWS via AWS Organizations.",
             "Facilita o gerenciamento das contas AWS, introduzindo governança, organização e segurança."),
            ("Conta Network (Rede)",
             "Centralizar todos os recursos de rede e conectividade (Transit Gateway, VPN).",
             "Isola a complexidade da rede, aplicando políticas de segurança consistentes."),
            ("Conta Development (Desenvolvimento)",
             "Hospedar ambientes de desenvolvimento e testes não críticos.",
             "Permite inovação rápida sem risco ao ambiente de produção."),
            ("Conta Production (Produção)",
             "Hospedar aplicações e serviços críticos que atendem usuários finais.",
             "Garante o mais alto nível de segurança e isolamento para serviços de missão crítica."),
        ]:
            _heading(doc, nome, level=3, color=NAVY)
            _kv(doc, "Função Principal", funcao)
            _kv(doc, "Benefício", beneficio)

    # Outros serviços (AWS Backup, etc.)
    for svc in outros_svc:
        if not isinstance(svc, dict):
            continue
        nome   = svc.get("nome", "")
        intro  = svc.get("intro", "")
        bullets = svc.get("bullets") or []
        if nome:
            _heading(doc, nome, level=2, color=NAVY)
        if intro:
            _body(doc, intro)
        for b in bullets:
            _bullet(doc, str(b))

    # If no outros_servicos from narrative, add default AWS Backup block
    if not outros_svc:
        _heading(doc, "AWS Backup", level=2, color=NAVY)
        _body(doc, (
            "O AWS Backup permite centralizar e automatizar políticas de backup para recursos "
            f"AWS no ambiente de {client.company}. A adoção correta do serviço permitiria:"
        ))
        _bullet(doc, "Padronizar políticas de backup para volumes EBS associados às instâncias EC2.")
        _bullet(doc, "Definir políticas de retenção conforme criticidade do workload.")
        _bullet(doc, "Simplificar a gestão operacional de backups com um único plano centralizado.")

    doc.add_page_break()

    # ═════════════════════════════════════════════════════════════════════
    # CONSIDERAÇÕES GERAIS
    # ═════════════════════════════════════════════════════════════════════
    _heading(doc, "Considerações Gerais", level=1, color=PINK)

    intro_consider = consider.get("introducao", "")
    if intro_consider:
        _body(doc, intro_consider)
    else:
        _body(doc, (
            f"A arquitetura atual de {client.company} na AWS possui pontos de melhoria em termos "
            f"de segurança, governança e eficiência de custos, principalmente por meio da "
            f"padronização e consolidação dos recursos existentes."
        ))

    # Organização e Governança
    org_bullets = consider.get("organizacao_governanca") or []
    if org_bullets:
        _heading(doc, "Organização e Governança", level=2, color=NAVY)
        for b in org_bullets:
            _bullet(doc, str(b))

    # Rede, Segurança e Acesso
    vpc_bullets = consider.get("vpc") or []
    seg_bullets = consider.get("seguranca") or []
    acc_bullets = consider.get("acesso") or []

    if vpc_bullets or seg_bullets or acc_bullets:
        _heading(doc, "Rede, Segurança e Acesso", level=2, color=NAVY)

        if vpc_bullets:
            p = doc.add_paragraph()
            r = p.add_run("VPC")
            _font(r, bold=True, color=NAVY)
            for b in vpc_bullets:
                _bullet(doc, str(b), indent_cm=0.5)

        if seg_bullets:
            p = doc.add_paragraph()
            r = p.add_run("Segurança")
            _font(r, bold=True, color=NAVY)
            for b in seg_bullets:
                _bullet(doc, str(b), indent_cm=0.5)

        if acc_bullets:
            p = doc.add_paragraph()
            r = p.add_run("Acesso")
            _font(r, bold=True, color=NAVY)
            for b in acc_bullets:
                _bullet(doc, str(b), indent_cm=0.5)

    # Performance e FinOps
    finops_bullets = consider.get("performance_finops") or []
    if not finops_bullets:
        # build from raw data as fallback
        finops_bullets = []
        if savings_total > 0:
            finops_bullets.append(
                f"Economia potencial identificada de ${savings_total:.0f}/mês "
                f"({report.savings_percentage or 0:.1f}% de redução possível)."
            )
        if sp_recs:
            sp_total = sum(float(sp.get("hourly_commitment", 0)) * 730 for sp in sp_recs)
            if sp_total:
                finops_bullets.append(
                    f"Savings Plans: aquisição de compromissos pode reduzir custos de computação em até 60%."
                )
        if no_lifecycle:
            finops_bullets.append(
                f"Implementar S3 Lifecycle Policies em {no_lifecycle} bucket(s) para reduzir custos de armazenamento."
            )
        if rightsizing:
            finops_bullets.append(
                f"Rightsizing de {len(rightsizing)} instância(s) EC2 superdimensionadas identificadas pelo Compute Optimizer."
            )

    if finops_bullets:
        _heading(doc, "Recomendações de Performance e FinOps", level=2, color=NAVY)
        for b in finops_bullets:
            _bullet(doc, str(b))

    doc.add_page_break()

    # ═════════════════════════════════════════════════════════════════════
    # PAIN POINTS
    # ═════════════════════════════════════════════════════════════════════
    _heading(doc, "Pain Points", level=1, color=PINK)
    _body(doc, "Ações críticas e imediatas para execução após alinhamento:")

    # Use AI-generated pain points if available, else build from raw data
    if pain_pts:
        for pp in pain_pts:
            _bullet(doc, str(pp))
    else:
        # fallback
        if iam.get("root_mfa_enabled") is False:
            _bullet(doc, "Habilitar MFA na conta root imediatamente — risco crítico de segurança.")
        if no_mfa:
            _bullet(doc, f"Habilitar MFA para {len(no_mfa)} usuário(s) IAM sem autenticação multifator.")
        if old_keys:
            _bullet(doc, f"Rotacionar {len(old_keys)} chave(s) de acesso com mais de 90 dias.")
        if public_bkts:
            _bullet(doc, f"Bloquear acesso público em {len(public_bkts)} bucket(s) S3 expostos.")
        if open_sgs:
            _bullet(doc, f"Revisar {len(open_sgs)} Security Group(s) com portas abertas para 0.0.0.0/0.")
        if no_guardduty:
            _bullet(doc, f"Habilitar GuardDuty nas regiões sem monitoramento: {', '.join(no_guardduty[:5])}.")
        if vpcs_no_flow:
            _bullet(doc, f"Ativar VPC Flow Logs em {len(vpcs_no_flow)} VPC(s) para visibilidade de tráfego.")
        if unattached:
            _bullet(doc, f"Remover ou snapshottear {len(unattached)} volume(s) EBS desanexados gerando custo.")
        if no_lifecycle:
            _bullet(doc, f"Implementar S3 Lifecycle Policy em {no_lifecycle} bucket(s) sem política de ciclo de vida.")
        if enc_ebs:
            _bullet(doc, f"Habilitar criptografia em {len(enc_ebs)} volume(s) EBS sem criptografia em repouso.")

    # ═════════════════════════════════════════════════════════════════════
    # OPORTUNIDADES
    # ═════════════════════════════════════════════════════════════════════
    if opps or savings_total > 0 or sp_recs or unattached:
        doc.add_paragraph()
        _heading(doc, "Oportunidades", level=1, color=PINK)
        _body(doc, "Oportunidades para um projeto de modernização e refactoring de infraestrutura:")

        if opps:
            for opp in opps:
                _bullet(doc, str(opp))
        else:
            # fallback
            if savings_total > 0:
                _bullet(doc, f"Implementar otimizações identificadas para reduzir ${savings_total:.0f}/mês ({report.savings_percentage or 0:.1f}% do custo atual).")
            if sp_recs:
                _bullet(doc, "Expandir cobertura de Savings Plans para reduzir exposição ao preço On-Demand.")
            if unattached:
                _bullet(doc, f"Eliminar {len(unattached)} volume(s) EBS ocioso(s) e revisar política de snapshots.")
            if no_lifecycle:
                _bullet(doc, f"Configurar políticas de S3 Lifecycle para logs (S3 Intelligent-Tiering e Glacier Instant Retrieval).")
            if rightsizing:
                _bullet(doc, f"Aplicar recomendações de rightsizing do Compute Optimizer em {len(rightsizing)} instância(s).")
            _bullet(doc, "Implementar governança multi-conta através de AWS Organizations e Landing Zone.")
            _bullet(doc, "Adotar AWS Backup para orquestração centralizada de snapshots EBS e RDS.")

        doc.add_page_break()

    # ═════════════════════════════════════════════════════════════════════
    # REFERÊNCIAS
    # ═════════════════════════════════════════════════════════════════════
    _heading(doc, "Referências", level=1, color=PINK)
    refs = [
        ("AWS Well-Architected Framework",
         "https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html"),
        ("IAM Best Practices",
         "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"),
        ("AWS Backup",
         "https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html"),
        ("Landing Zones",
         "https://docs.aws.amazon.com/controltower/latest/userguide/landing-zone.html"),
        ("AWS Organizations",
         "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html"),
        ("Amazon RDS",
         "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Welcome.html"),
        ("AWS Savings Plans",
         "https://docs.aws.amazon.com/savingsplans/latest/userguide/what-is-savings-plans.html"),
        ("Amazon GuardDuty",
         "https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html"),
        ("AWS Security Hub",
         "https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html"),
        ("AWS Cost Explorer",
         "https://docs.aws.amazon.com/cost-management/latest/userguide/ce-what-is.html"),
    ]
    for name, url in refs:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(6)
        r1 = p.add_run(f"• {name}: ")
        _font(r1, bold=True, color=NAVY)
        r2 = p.add_run(url)
        _font(r2, color=BLUE)

    doc.add_paragraph()
    p_footer = doc.add_paragraph()
    p_footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p_footer.add_run(
        f"Documento gerado automaticamente em "
        f"{datetime.utcnow().strftime('%d/%m/%Y às %H:%M')} UTC"
    )
    _font(r, size=9, italic=True, color=LIGHT_GRAY)

    # ── save ──────────────────────────────────────────────────────────────
    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf
