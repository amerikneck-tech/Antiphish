"""Analyze a real .eml file:  python parse_eml.py path/to/email.eml [--llm] [--json out.json]"""
import sys

from antiphish.detector import analyze_eml, export_json

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parse_eml.py email.eml [--json output.json]")
        sys.exit(1)
    eml_path = sys.argv[1]
    result = analyze_eml(eml_path, use_llm="--llm" in sys.argv)
    print(f"Score: {result['score']}  ->  {result['level']}")
    print("Verdict:", result["verdict"])
    print("ML phishing probability:", result["ml_phishing_probability"])
    for sig in result["signals"][:12]:
        print(f"  - ({sig['weight']}) {sig['signal']}: {sig['detail']}")
    if result.get("attachment_findings"):
        print("Attachment analysis:")
        for line in result["attachment_findings"][:20]:
            print("   *", line)
    if "--json" in sys.argv:
        out = sys.argv[sys.argv.index("--json") + 1]
        export_json(result, out)
        print("JSON report saved to", out)
