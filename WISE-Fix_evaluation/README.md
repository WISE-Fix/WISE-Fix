
# WISE-Fix

WISE-Fix validates and freezes weakness-specific verifier suites, executes linked Precondition, Repair, and Safety checks, and ranks only Verified patches. Online verification requires no LLM calls.

## Installation

Requires Python 3.10+ and Git.

```bash
python -m pip install -r requirements.txt
```

## Datasets

[Click here to download the datasets](https://drive.google.com/drive/folders/1-Rc_LidaG1I7ZOzp0nJjXlEESoGGVXvj?usp=sharing).

Each dataset folder must contain `train.jsonl`, `dev.jsonl`, and `test.jsonl`. Multiple datasets may use separate subfolders.


## Execution

```bash
python wise-fix.py --input /path/to/input_folder --output /path/to/output_folder
```

To specify verifier suites and configuration:

```bash
python wise-fix.py --input /path/to/input_folder --output /path/to/output_folder --suites /path/to/suites_folder --config /path/to/config.json
```

For offline LLM synthesis or revision, provide CWE specifications in `input_folder/cwe_specs/`:

```bash
export DEEPSEEK_API_KEY="your-api-key"
python wise-fix.py --input /path/to/input_folder --output /path/to/output_folder --suites /path/to/suites_folder --cwes CWE-119 CWE-125 --endpoint https://YOUR_API_HOST/v1 --model YOUR_MODEL
```



## Outputs

The output folder contains frozen artifacts, verdicts, evidence, classification metrics, and per-CWE ranked Verified patches.
