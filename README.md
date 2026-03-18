# Abuse Investigation Lab

This repository demonstrates how I detect and analyze abuse patterns using structured logs, anomaly detection, and simple AI-assisted logic.

## Objective

Identify suspicious behavior patterns such as:
- Repeated failed logins
- High-frequency transactions
- Unusual IP activity
- Behavioral anomalies across time

## Investigation Workflow

1. Ingest logs (JSON format)
2. Analyze frequency + anomalies
3. Flag suspicious entities
4. Output structured alerts

## Example Signals

- >5 login failures in short window
- Transactions above normal threshold
- Rapid repeated actions (bot-like behavior)

## Why This Matters

Abuse detection is not about single events — it’s about **patterns over time**.

This project demonstrates:
- Signal correlation
- Behavioral analysis
- Structured investigation logic

## Next Steps

- Add ML-based anomaly detection
- Integrate real-time log ingestion
- Expand classification modelso
