# IGA-Guard 动态手法 DSL 示例（P5）
# 用法: python scripts/register_techniques_dsl.py data/cache/technique_dsl_examples.dsl

technique discovered_triple_url:
  template: repeat_url_encode
  attack_types: [SQLi, CMD]
  match: "%25%25"
  note: "三重 URL 编码漏检驱动"

technique discovered_json_null_key:
  template: json_null_in_key
  attack_types: [SQLi]
  match: "\\x00"
  note: "JSON 键空字节注入"

technique discovered_md5_camouflage:
  template: md5_hex32_camouflage
  attack_types: [SQLi]
  match: "^[0-9a-fA-F]{32}$"
  note: "MD5 十六进制伪装"
