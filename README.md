# MiniGreyWebFuzz

MiniGreyWebFuzz is a lightweight Python prototype for feedback-guided fuzzing of Flask web applications. It is designed as an educational, research-style project that demonstrates web crawling, mutation-based fuzzing, and simple response/coverage feedback for endpoint exploration.

## Overview

This project includes:
- A local intentionally branch-heavy Flask target app.
- A small web fuzzer that discovers endpoints/forms, mutates parameters, executes requests, and prioritizes interesting behavior.
- A comparison between naive random fuzzing and lightweight feedback-guided fuzzing.

It is intentionally scoped for local experimentation and undergraduate-level security research demos.

## What "Feedback-Guided" Means Here

In this project, feedback-guided fuzzing means the fuzzer does not treat all responses equally. After each request, it scores the result using signals such as:
- newly observed lightweight coverage IDs,
- new status codes,
- error-like response keywords,
- request exceptions,
- reflected inputs.

High-signal requests are re-queued with higher priority (in bounded fashion), so the scheduler spends more budget on behaviors that appear to reach new logic paths.

## Lightweight Coverage Note

Coverage in MiniGreyWebFuzz is lightweight route/branch instrumentation from the demo Flask app (`target_app/coverage_tracker.py`), not bytecode or source-level instrumentation. Each target endpoint marks branch IDs, and the fuzzer reads them through `GET /__coverage`.

## Features

- Crawls same-origin links and HTML forms
- Extracts GET/POST request templates
- Mutation-based parameter fuzzing with reusable payload families
- Reflection detection in responses
- Error keyword detection for suspicious server behavior
- Lightweight app-side coverage feedback (`/__coverage`)
- Two modes: `random` and `feedback`
- JSON and Markdown run reports

## Repository Structure

- `target_app/`: Demo Flask application and in-memory coverage tracker
- `fuzzer/`: Crawler, mutator, executor, analyzer, scheduler, reporting, CLI
- `tests/`: Unit tests for mutator and feedback logic
- `reports/`: Generated run artifacts (`findings.json`, `summary.md`)

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running the Target App

```bash
python target_app/app.py
```

The demo app listens on `http://127.0.0.1:5000`.

## Running the Fuzzer

Feedback-guided mode:

```bash
python -m fuzzer.main --base-url http://127.0.0.1:5000 --max-requests 300 --mode feedback
```

Random mode:

```bash
python -m fuzzer.main --base-url http://127.0.0.1:5000 --max-requests 300 --mode random
```

Optional tuning flags:
- `--timeout`
- `--crawl-depth`
- `--crawl-pages`
- `--budget-per-param`

## Example Workflow

1. Start the Flask target app.
2. Run the fuzzer in `random` mode.
3. Save reports from `reports/findings.json` and `reports/summary.md`.
4. Reset and run in `feedback` mode with the same request budget.
5. Compare coverage IDs, unique statuses, and top findings.

## Architecture

```text
Flask app -> crawler -> templates -> mutator -> executor -> feedback -> scheduler -> report
```

## How Feedback Mode Differs from Random

- `random`: Shuffles and executes generated fuzz requests without learning.
- `feedback`: Uses result scoring and bounded priority re-enqueueing to revisit higher-value requests.

In this project, feedback mode is still lightweight and understandable, but usually reaches rare branches faster than random mode.

## Why This Is Closer to Grey-Box Fuzzing

Pure random testing is black-box and mostly response-driven. MiniGreyWebFuzz adds explicit instrumentation feedback (`/__coverage`) from inside the demo app, so scheduling decisions are partially guided by internal execution hints. That makes it closer to grey-box fuzzing than pure random mutation.

## Example Evaluation

Sample table (illustrative only): fixed-budget comparison at 300 requests.

| Mode     | Requests | Unique Coverage IDs | Unique Status Codes | Findings |
|----------|----------|---------------------|---------------------|----------|
| random   | 300      | 10-14               | 5-7                 | 20-35    |
| feedback | 300      | 15-22               | 6-9                 | 30-55    |

Interpretation: feedback mode typically discovers more branch IDs and unusual responses with the same request budget.

## Design Tradeoffs

- HTML-only crawling: keeps implementation lightweight and deterministic for a local Flask demo, but does not execute JavaScript.
- Lightweight coverage: branch IDs are app-provided markers (`/__coverage`) rather than deep instrumentation, which keeps setup simple and educational.
- Bounded mutator and scheduling: request generation, replay, and child mutations are capped to avoid queue explosion and keep behavior understandable.

## Example Findings

Depending on run budget and mode, the fuzzer can surface:
- New HTTP statuses from malformed or boundary inputs
- Reflected payloads in `/search` and `/profile`
- Rare branch coverage in `/debug`, `/item`, and `/login`
- Responses containing warning/error-like keywords

## Limitations

- No JavaScript rendering or dynamic DOM execution
- No complex authentication/session workflows
- Not production-ready and not a full vulnerability scanner
- Evaluated primarily on the included local Flask demo app

## Future Work

- Session-aware crawling and stateful flows
- Grammar-based parameter mutation
- Dedicated API fuzzing mode (JSON bodies/headers)
- Crash/error clustering for triage
- Richer coverage guidance and response similarity analysis

## Educational Note

This project is for local educational fuzzing on the included demo application. Only test systems you own or are explicitly authorized to assess.
