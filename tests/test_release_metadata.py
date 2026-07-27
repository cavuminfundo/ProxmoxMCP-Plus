import ast
import json
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def _setup_kwargs() -> dict[str, object]:
    tree = ast.parse((ROOT / "setup.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "setup":
            values: dict[str, object] = {}
            for kw in node.keywords:
                if not kw.arg:
                    continue
                try:
                    values[kw.arg] = ast.literal_eval(kw.value)
                except ValueError:
                    continue
            return values
    raise AssertionError("setup.py does not call setup()")


def test_release_versions_are_aligned():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    setup_kwargs = _setup_kwargs()
    package_init: dict[str, object] = {}
    exec(
        compile(
            (ROOT / "src/proxmox_mcp/__init__.py").read_text(encoding="utf-8"),
            "__init__.py",
            "exec",
        ),
        package_init,
    )
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))

    version = pyproject["project"]["version"]
    assert setup_kwargs["version"] == version
    assert package_init["__version__"] == version
    assert manifest["version"] == version
    assert server["version"] == version
    assert {package["version"] for package in server["packages"]} == {version}


def test_setup_metadata_tracks_pyproject_runtime_contract():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    setup_kwargs = _setup_kwargs()

    assert setup_kwargs["name"] == pyproject["project"]["name"]
    assert setup_kwargs["python_requires"] == pyproject["project"]["requires-python"]
    assert set(setup_kwargs["install_requires"]) == set(
        pyproject["project"]["dependencies"]
    )
    assert set(setup_kwargs["entry_points"]["console_scripts"]) == {
        f"{name}={target}" for name, target in pyproject["project"]["scripts"].items()
    }
