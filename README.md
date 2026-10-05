# 🛠️ WISE-Fix Replication Package

> **WISE-Fix: Identifying Silent Security Patches via Weakness-Informed Executable Verification**

![WISE-Fix Approach Overview](<WISE-Fix Overview.png>)

This repository provides the replication materials for WISE-Fix, covering dataset preparation, baseline comparisons, verifier construction, online detection, and evaluation. The package is under preparation; runnable commands will be added alongside the corresponding implementations.

## 🧭 1. Framework Overview

WISE-Fix identifies silent vulnerability-fixing patches by linking evidence across the **pre-patch state**, **code change**, and **post-patch state**.

- **Offline:** An LLM uses CWE specifications and labeled training transitions to synthesize weakness-specific Precondition, Repair, and Safety obligations from fixed analysis operators. Accepted suites are validated, frozen, and versioned.
- **Online:** Frozen verifiers examine candidate patches and use bounded commit-group search when required evidence remains unresolved.
- **Output:** Each candidate receives a **Verified**, **Rejected**, or **Inconclusive** verdict with traceable evidence. Only Verified candidates are ranked.

**Online detection uses no LLM inference or rule adaptation.**

## 📊 2. Datasets

We evaluate WISE-Fix on **PatchDB\*** and **SPI-DB\***, the repository-level benchmarks introduced by RepoSPD. Both include security and non-security patches with source-tree and dependency context.

| Dataset | Training | Validation | Test |
| --- | ---: | ---: | ---: |
| PatchDB* | 23,229 | 2,907 | 2,906 |
| SPI-DB* | 16,454 | 2,028 | 2,000 |

Training data support verifier synthesis and scorer fitting. Validation data guide bounded revision, suite acceptance, and configuration selection. Test labels and CWE annotations are used only for evaluation and group reporting.

Dataset access information is available in [Datasets/](./Datasets/), including [Datasets_link.txt](./Datasets/Datasets_link.txt).

## 📂 3. Repository Structure

| Path | Contents |
| --- | --- |
| [Datasets/](./Datasets/) | Dataset links, split information, and preparation instructions. |
| [Baselines/](./Baselines/) | Reproduction materials for RepoSPD and RepoSPD–DeepSeek. |
| [WISE-Fix_evaluation/](./WISE-Fix_evaluation/) | WISE-Fix evaluation materials and reproduction instructions. |
| `WISE-Fix Overview.png` | Approach overview diagram. |
| `README.md` | Package overview and usage guide. |

## 🚀 4. Environment Setup

Use an isolated environment for reproducibility.

The tested Python version, analysis toolchain, dependency versions, and installation commands will be provided with the executable release. Baseline-specific requirements will be documented in [Baselines/](./Baselines/).

## 🔄 5. Detailed Workflow

### Phase 1: Offline Verifier Synthesis

The LLM receives a CWE specification, labeled training transitions, a fixed operator library, and an obligation schema. It generates linked Precondition, Repair, and Safety obligations with explicit evidence requirements and compatible cross-stage bindings.

### Phase 2: Validation and Artifact Freezing

Candidate suites undergo schema and type checks, compilation, smoke tests, and development validation.

Acceptance requires precision and recall of at least 0.80 and compliance with the configured FPR threshold. Up to three revisions are allowed after initial evaluation. Suites that fail the checks or exhaust the revision budget without acceptance are marked **Unsupported**.

Accepted suites are packaged with the operators, evidence validator, decision rules, configuration, feature extractor, and fitted ranking scorer. Artifacts are versioned and protected by SHA-256 integrity checks.

### Phase 3: Sequential Verification

For each candidate, WISE-Fix constructs `(S_before, diff, S_after)` with bounded source and dependency context, then executes:

- **Precondition:** Establish the encoded weakness condition before the patch.
- **Repair:** Link an explicit edit to the corresponding repair relation.
- **Safety:** Establish the encoded post-repair property.

Each stage returns **Satisfied**, **Violated**, or **Unresolved**, together with supporting or contradictory evidence and missing requirements.

### Phase 4: Obligation-Guided Commit-Group Search

Search begins only when mandatory obligations remain unresolved and no stage is violated.

WISE-Fix explores bounded, ancestry-compatible commit groups using fixed structural, dependency, and temporal relations. Evaluation admits only the seed and eligible ancestors at the cutoff, excluding later completing commits.

A satisfied composite group also requires confirmation in the seed’s actual post-patch state and evidence that the seed contributes a required mitigating change.

### Phase 5: Evidence Validation and Ranking

The evidence validator checks provenance, scope, correspondence, completeness, consistency, and witness compatibility. Frozen rules then assign:

- **Verified:** The required obligations and applicable contribution requirements are established by validated evidence.
- **Rejected:** Validated evidence establishes a seed-applicable rejection condition.
- **Inconclusive:** Neither verification nor rejection is established.

Within a weakness suite, validated rejection takes precedence. Across suites, any Verified result verifies the candidate. Otherwise, any Inconclusive result—or no applicable suite—yields Inconclusive; remaining cases are Rejected.

Only Verified candidates are ranked. Ranking scores do not change verdicts.

Verification establishes the encoded obligations within the configured analysis scope.

## 📝 6. Verifier Synthesis Interface

**Inputs:** Target CWE, CWE specification, positive and negative training transitions, fixed operators, and output schema.

**Task:** Generate Precondition, Repair, and Safety obligations specifying scopes, selectors, predicates, bindings, aggregation, and evidence requirements. Keep repair alternatives distinct and preserve compatible cross-stage bindings.

**Output:** Schema-conforming JSON compiled into deterministic executable verifiers.

**Constraints:** Use only permitted operators and code-derived runtime evidence. Exclude labels and identifying metadata from predicates. Invoke no LLM during execution, and leave final verdict assignment to the frozen decision module.

The full prompts, operator contracts, and JSON schema will accompany the executable release.

## 🔑 7. LLM API Configuration

The manuscript uses **deepseek-v4-flash** for offline synthesis and revision.

- **Offline artifact rebuilding** requires access to the configured LLM service.
- **Detection with frozen artifacts** requires no LLM API key.
- **RepoSPD–DeepSeek** uses online LLM inference for direct patch classification.

API configuration and model settings will be documented with the scripts. Keep API keys outside the repository.

## 🧪 8. Reproducing the Experiments

| Research Question | Evaluation |
| --- | --- |
| RQ1: Effectiveness | Comparison with RepoSPD and RepoSPD–DeepSeek. |
| RQ2: Verifier Quality | Expert stage judgments, tri-state agreement, and evidence-contract compliance. |
| RQ3: Weakness-Informed Verification | Agnostic-suite comparison and cross-category selectivity. |
| RQ4: Verification Components | Stage acceptance-gate and multi-commit processing ablations. |
| RQ5: Robustness | Weakness groups, repository domains, and negative-patch difficulty. |
| RQ6: Efficiency | Offline LLM costs and post-retrieval online processing costs. |

Stage ablations remove the corresponding acceptance requirement while retaining stage execution, bindings, rejection conditions, compatibility checks, and search triggers. The multi-commit ablation jointly disables upfront multi-commit context construction and commit-group search.

For binary evaluation, **Verified** is positive; **Rejected** and **Inconclusive** are non-positive. Each seed is counted once, while the distinct tri-state outcomes remain recorded.

Execution commands and expected outputs will be provided in [WISE-Fix_evaluation/](./WISE-Fix_evaluation/).

## 🖥️ 9. Hardware and Timing

Online measurements in the manuscript use an **NVIDIA RTX 3090 system**. This describes the experimental environment, not a minimum hardware requirement.

Offline timing covers LLM synthesis and revision, excluding local artifact preparation. Online timing covers post-retrieval processing, excluding repository-wide retrieval.

## 📚 10. Citation and License

Citation metadata, the code license, and upstream dataset licensing information will be added before the completed replication release.
