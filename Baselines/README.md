# RepoSPD–DeepSeek

Direct online LLM classification using RepoSPD context. Requires Python 3.10+ and an LLM API key.

## Run

```bash
export DEEPSEEK_API_KEY="your-api-key"

python repospd_deepseek.py \
  --input /path/to/shared_dataset_folder \
  --output /path/to/baseline_output_folder \
  --endpoint https://YOUR_API_KEY/v1 \
  --model deepseek-v4-flash
```
