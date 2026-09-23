import argparse
import ast
import json
import sys
from pathlib import Path

TYPE_MAP = {
    str: "string",
    bool: "boolean",
    int: "number",
    float: "number",
}


def extract_defaults(config_path: Path) -> dict[str, object]:
    tree = ast.parse(config_path.read_text(encoding="utf-8"), filename=str(config_path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
                and target.attr == "_defaults"
            ):
                if not isinstance(node.value, ast.Dict):
                    raise ValueError("McritConfig._defaults must be a dictionary literal")
                return ast.literal_eval(node.value)
    raise ValueError(f"Could not find McritConfig._defaults in {config_path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, help="Path to the repository root")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    config_path = repo / "mcrit_plugin" / "core" / "config.py"
    plugin_path = repo / "mcrit_plugin" / "ida" / "ida-plugin.json"

    defaults = extract_defaults(config_path)
    plugin_data = json.loads(plugin_path.read_text(encoding="utf-8"))
    settings = {setting["key"]: setting for setting in plugin_data["plugin"]["settings"]}

    print(f"[INFO] mcrit_plugin/core/config.py defaults keys: {len(defaults)}")
    print(f"[INFO] ida-plugin.json settings keys: {len(settings)}")

    failures: list[str] = []

    shared_path = repo / "mcrit_plugin" / "core" / "settings.json"
    shared_settings = json.loads(shared_path.read_text(encoding="utf-8"))
    if shared_settings != plugin_data["plugin"]["settings"]:
        failures.append(
            "mcrit_plugin/core/settings.json must be identical to the ida-plugin.json settings array"
        )

    default_keys = set(defaults)
    setting_keys = set(settings)

    missing_in_json = sorted(default_keys - setting_keys)
    missing_in_config = sorted(setting_keys - default_keys)

    for key in missing_in_json:
        failures.append(f"Missing setting in ida-plugin.json: {key}")
    for key in missing_in_config:
        failures.append(f"Missing default in mcrit_plugin/core/config.py: {key}")

    for key in sorted(default_keys & setting_keys):
        default_value = defaults[key]
        expected_type = TYPE_MAP.get(type(default_value))
        actual_type = settings[key]["type"]
        actual_default = settings[key].get("default")

        if expected_type and actual_type != expected_type:
            failures.append(
                f"Type mismatch for {key}: mcrit_plugin/core/config.py infers {expected_type}, ida-plugin.json declares {actual_type}"
            )
        if actual_default != default_value:
            failures.append(
                f"Default mismatch for {key}: mcrit_plugin/core/config.py has {default_value!r}, ida-plugin.json has {actual_default!r}"
            )

    if failures:
        print("[FAIL] Settings consistency checks failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("[PASS] Settings consistency checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
