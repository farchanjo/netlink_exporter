---
status: accepted
date: 2026-05-29
deciders: [eonf]
consulted: []
informed: []
---

# Record architecture decisions

## Context and Problem Statement

The nft_exporter architecture needs a durable, reviewable record of
significant decisions. How should those decisions be captured?

## Considered Options

- MADR 4.0 markdown files under `adr/`
- An external wiki
- No formal record

## Decision Outcome

Chosen option: "MADR 4.0 markdown files under `adr/`", because the
records live beside the schemas they constrain and are validated by
`spec validate`.
