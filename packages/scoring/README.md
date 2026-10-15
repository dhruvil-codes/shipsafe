# @shipsafe/scoring

Versioned security scoring (`v1.0`) + deterministic finding explainer.
Pure functions, no I/O, no LLM.

## score.ts

- `computeScore(findings, assessedControls, applicableControls)` →
  `SecurityScore` (`overall`, `grade` A/B/C/F, `coverage`, `capped`,
  `banner?`, `categoryScores`, `scoringVersion: 'v1.0'`).
- Weights: auth 25 / api 20 / source 20 / storage 15 / web 10 / logging 10,
  renormalized over assessed categories (categories with confirmed findings;
  all six when controls were assessed with zero findings; none — overall 0 —
  when nothing ran).
- Penalties: CRITICAL 40, HIGH 20, MEDIUM 8, LOW 2, INFO 0. Only `confirmed`
  findings score. Any confirmed CRITICAL caps overall at 40 with banner
  `"Critical finding caps score at 40"`. Coverage is assessed/applicable*100
  (1 decimal, 0 when applicable is 0). Grades: ≥90 A, ≥70 B, ≥50 C, else F.
- Also exports `gradeFor`, `CATEGORY_WEIGHTS`, `SEVERITY_PENALTIES`,
  `SCORING_VERSION`, `CRITICAL_CAP`, `CRITICAL_BANNER`.

## explainer.ts

- `explain(finding)` → `{ what, why, fix, verify }` from deterministic
  per-ruleId templates (fix carries a copy-pasteable snippet). Unknown rule
  IDs fall back to the finding's own text — vulnerabilities are never invented.
