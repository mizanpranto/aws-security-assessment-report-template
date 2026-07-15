# ☁️ AWS Security Assessment Report Template

> **Professional PDF report generator for AWS security assessments.**  
> Built for cloud security consultants delivering findings to startups and SMEs.  
> Enter client info step-by-step via interactive terminal wizard — no code editing required.

---

## 📋 What This Does

Run one command. Answer questions one by one. Get a client-ready PDF.

The tool generates a complete **AWS Security Assessment Report** with:

- ✅ Cover page — client name, AWS account ID, consultant credentials, confidentiality notice
- ✅ Table of contents
- ✅ Executive summary — auto-generated from your findings
- ✅ Security score (0–100) — auto-calculated with severity-weighted deductions
- ✅ Finding breakdown — Critical / High / Medium / Low counts
- ✅ Detailed finding cards — description, impact, recommendation, CIS reference
- ✅ Prioritised remediation roadmap — auto-grouped by severity
- ✅ AWS services reference appendix
- ✅ Branded header & footer on every page

---

## 🚀 Quick Start

```bash
# 1. Install the only dependency
pip install reportlab

# 2. Run the wizard
python generate_report.py

# 3. Answer questions step by step — done!
# Output: aws_security_report_<clientname>.pdf
```

---

## 🖥️ Interactive Wizard — What It Looks Like

```
╔══════════════════════════════════════════════════════════╗
║     AWS SECURITY ASSESSMENT REPORT GENERATOR            ║
║     Cloud Security Consultant Tool                      ║
╚══════════════════════════════════════════════════════════╝

──────────────────────────────────────────────────────────
  STEP 1 of 4 — YOUR CONSULTANT DETAILS
──────────────────────────────────────────────────────────
  Your full name [Your Name]: Mohammed Rahman
  Your title [Cloud Security Consultant]: Cloud Security Consultant
  Your email [hello@yoursite.com]: hello@yoursite.com
  Your certifications: AWS SAA Certified | ISO 27001 | NIST | GDPR

──────────────────────────────────────────────────────────
  STEP 2 of 4 — CLIENT DETAILS
──────────────────────────────────────────────────────────
  Client company name: TechFlow SaaS Ltd
  Client industry: SaaS / B2B
  AWS Account ID (12 digits): 987654321098

──────────────────────────────────────────────────────────
  STEP 3 of 4 — ASSESSMENT SCOPE
──────────────────────────────────────────────────────────
  1. IAM Users & Roles
  2. S3 Bucket Configurations
  3. EC2 Security Groups
  4. CloudTrail & Logging
  (blank line to finish)

──────────────────────────────────────────────────────────
  STEP 4 of 4 — FINDINGS
──────────────────────────────────────────────────────────

  ── Finding #1 (AWF-001) ──
  Title: Root Account Has Active Access Keys
  Severity:  1) CRITICAL   2) HIGH   3) MEDIUM   4) LOW
  Choose [1-4]: 1
  Category: IAM
  Description: The AWS root account has active programmatic access keys...
  Impact: Complete account compromise if keys are leaked.
  Recommendation: Delete all root access keys immediately...
  Reference: AWS CIS Benchmark v1.5 — Control 1.4

  ✅ Finding AWF-001 saved.

  ── Finding #2 (AWF-002) ──
  Title: done    ← type 'done' when finished

──────────────────────────────────────────────────────────
  AUTO-GENERATING EXECUTIVE SUMMARY & ROADMAP
──────────────────────────────────────────────────────────
  ✅ Executive summary generated automatically.
  ✅ Security score: 42/100 (NEEDS IMPROVEMENT)
  ✅ Remediation roadmap built from 5 findings.

  Output PDF filename: aws_security_report_techflow.pdf
  ⏳ Generating PDF report...

  REPORT READY: aws_security_report_techflow.pdf
```

---

## 📊 Security Score Calculation

| Severity | Deduction per finding |
|----------|-----------------------|
| CRITICAL | -20 points |
| HIGH     | -10 points |
| MEDIUM   | -5 points  |
| LOW      | -2 points  |

| Score Range | Rating |
|-------------|--------|
| 80–100 | ✅ GOOD |
| 60–79  | 🟡 FAIR |
| 40–59  | 🟠 NEEDS IMPROVEMENT |
| 0–39   | 🔴 CRITICAL RISK |

---

## 📁 Report Sections

| # | Section | Content |
|---|---------|---------|
| Cover | — | Client info, consultant credentials, CONFIDENTIAL stamp |
| 1 | Executive Summary | Auto-generated narrative + security score box |
| 2 | Assessment Scope | Areas reviewed during the engagement |
| 3 | Risk Summary | Category breakdown table |
| 4 | Detailed Findings | Color-coded cards per finding |
| 5 | Remediation Roadmap | Phased fix plan by priority |
| 6 | Appendix | AWS security services reference |

---

## 🔍 Finding Severity Colors

| Severity | Color | Use When |
|----------|-------|----------|
| 🔴 CRITICAL | Red | Immediate risk of breach or data loss |
| 🟠 HIGH | Orange | Significant exposure, fix within 30 days |
| 🔵 MEDIUM | Blue | Moderate risk, fix within 90 days |
| 🟢 LOW | Green | Minor gaps, fix when possible |

---

## 📁 Project Structure

```
aws-security-assessment-report-template/
├── generate_report.py     # Full interactive report generator
└── README.md              # This file
```

---

## 🛠️ Requirements

- Python 3.8+
- `reportlab` library only (`pip install reportlab`)
- No AWS credentials needed — findings are entered manually after your assessment

---

## 💼 How This Fits Your Workflow

```
1. Conduct AWS assessment on client environment
         ↓
2. Note your findings (IAM gaps, S3 exposure, etc.)
         ↓
3. Run: python generate_report.py
         ↓
4. Enter client details + findings one by one
         ↓
5. PDF report generated in seconds
         ↓
6. Deliver to client 
```

---

## 👤 About

Built by **Mizanur_Rahman_Pranto** — Cloud Security Consultant  
Specialising in AWS security assessments for startups and SMEs globally.


- 💼 [LinkedIn](https://www.linkedin.com/in/mrpranto1997/)
- 📧 mprantox41@gmail.com
- 🏅 AWS SAA Certified | ISO 27001 | NIST | GDPR


---

## ⚠️ Disclaimer

For use by qualified security consultants only. All findings should reflect actual assessment results. Sample outputs are fictional and for demonstration only.
