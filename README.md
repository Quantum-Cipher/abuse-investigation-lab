# Abuse Investigation Lab

A lightweight Python project that demonstrates how suspicious behavior can be identified from structured event logs using simple, explainable detection rules.

This repository is designed as a portfolio project for Trust & Safety, fraud analysis, and Abuse Investigator–style roles. It focuses on turning raw events into actionable findings through reproducible logic rather than opaque automation.

---

## Overview

Abuse detection is rarely about a single event. It is usually about a pattern that emerges across users, IP addresses, actions, and time.

This project simulates a small investigation pipeline that:

- loads JSON event logs
- aggregates behavior by user and IP
- detects suspicious activity using clear rules
- prints a structured investigation summary
- writes a machine-readable report to `investigation_report.json`

The goal is to show practical reasoning, signal correlation, and investigative workflow design in a form that is easy to review.

---

## Why This Matters

Trust & Safety and abuse investigation teams often need to:

- identify repeated suspicious behavior
- correlate signals across accounts and infrastructure
- distinguish isolated noise from meaningful patterns
- produce clear, evidence-based summaries

This repository demonstrates those fundamentals in a minimal, readable format.

---

## Detection Rules

The detector currently flags the following patterns:

1. **Excessive login failures**
   - Triggered when a user exceeds a defined threshold of failed login attempts

2. **High-value transactions**
   - Triggered when a transaction amount exceeds a defined threshold

3. **Excessive password reset attempts**
   - Triggered when a user makes repeated password reset requests

4. **IP touching many accounts**
   - Triggered when a single IP address interacts with multiple distinct users

Each alert is assigned a severity level:
- `LOW`
- `MEDIUM`
- `HIGH`

---

## Repository Structure

```text
abuse-investigation-lab/
├── README.md
├── detector.py
├── sample_logs.json
├── requirements.txt
└── .gitignore