# WISE-Fix
## Identifying Silent Security Patches via Weakness-Informed Executable Verification

WISE-Fix identifies silent vulnerability-fixing patches by checking linked evidence across the **pre-patch state**, **code change**, and **post-patch state**.

## Approach Overview

![WISE-Fix Overview](<WISE-Fix Overview.png>)

### Offline: Synthesize, Validate, and Freeze

- **Synthesize:** An LLM composes fixed analysis operators into CWE-specific Precondition, Repair, and Safety verifier obligations using CWE specifications and labeled training transitions.
- **Validate:** Check suites on held-out development data and apply bounded revisions when acceptance criteria are not met.
- **Freeze:** Version accepted suites together with their operators, evidence validator, decision rules, configuration, and ranking scorer.

### Online: Verify, Recover Evidence, and Rank

- **Construct patch transitions:** Retrieve candidates and extract bounded source and dependency context for `(pre-patch state, diff, post-patch state)`.
- **Execute linked verifiers:**
  - **Precondition:** Establish the encoded weakness condition before the patch.
  - **Repair:** Link an explicit edit to the corresponding repair.
  - **Safety:** Establish the encoded post-repair property.
- **Recover missing evidence:** When mandatory obligations remain unresolved and no stage is violated, perform bounded, obligation-guided search over related commit groups.
- **Confirm composite repairs:** Check the selected witness in the seed’s actual post-patch state and establish the seed’s mitigating contribution.
- **Validate and decide:** Validate evidence and witness compatibility before assigning **Verified**, **Rejected**, or **Inconclusive**.
- **Rank:** Score only Verified patches using the frozen evidence scorer; ranking does not change verdicts.

**Online detection uses no LLM inference or rule adaptation.** Verification establishes encoded obligations within the configured analysis scope.
