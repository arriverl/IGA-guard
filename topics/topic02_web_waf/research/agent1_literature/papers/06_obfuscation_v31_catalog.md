# IGA-Guard v3.1 混淆技术扩库目录

> 来源：WAF-A-MoLE · ModSec-AdvLearn · WAFFLED · DEG-WAF · PAT · Prompt Injection 2025  
> 实现：`src/iga_guard/dataset/obfuscation_techniques.py` · `NEW_TECHNIQUES_V31`

## 新增 30 项（相对 v3.0 的 25 项基础库）

| 类别 | 技术名 | 攻击类型 |
|------|--------|----------|
| SQLi | `operator_swapping`, `integer_encoding`, `number_shuffling`, `comment_rewriting`, `logical_invariant_append`, `scientific_notation`, `between_tautology`, `conditional_block_comment`, `pipe_concat`, `backtick_identifier` | SQLi |
| 协议/结构 | `json_null_in_key`, `boundary_continuation_rfc2231` | 通用 |
| 路径/LFI | `mangled_path_dotdot`, `overlong_utf8_encoding`, `unicode_slash_encoding`, `reverse_proxy_path_delim`, `php_filter_wrapper`, `zip_stream_wrapper`, `xinclude_href_injection` | PathTraversal / FileInclusion / XXE |
| CMD | `ifs_var_bypass`, `brace_expansion_cmd`, `wildcard_glob_cmd`, `leetspeak_obfuscation` | CMD |
| XSS | `data_uri_xss`, `details_ontoggle_xss`, `string_fromcharcode_xss`, `invisible_css_conceal` | XSS |
| Prompt | `zero_width_char_split`, `homoglyph_substitution`, `system_log_masquerade` | PromptInjection |

## 扩库统计（`results/v3_augment_summary.json`）

- 输入：110,013 行 → 采样 20,000 攻击 → 新增 40,000 变种
- 输出：`train_obfuscated_v31.csv` **150,013** 行
- Top 技术：`boundary_continuation_rfc2231`, `brace_expansion_cmd`, `operator_swapping`

## 全量评测（`results/v2_exp1_v31.json`）

| 指标 | FP护栏前 | FP护栏 | **v3.1重训+护栏** |
|------|----------|--------|-------------------|
| 混淆 Recall | 97.94% | 92.32% | **91.17%** |
| Normal FPR | 11.16% | 4.23% | **3.42%** |
| 混淆 FN | 213 | 792 | **912** |

FPR 继续下降，混淆 Recall 仍距 99.5% 差约 8.3pp。下一步：912 条漏检入缓存 + `evolve-obf` + TinyBERT 在 v31 语料微调。
