import ast
from pathlib import Path


def _iter_python_files(root: Path):
    return sorted(root.rglob("*.py"))


def _contains_forbidden_import(tree: ast.AST, module: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == module:
                    return True
        if isinstance(node, ast.ImportFrom):
            if node.module and (node.module == module or node.module.startswith(f"{module}.")):
                return True
    return False


def _contains_forbidden_call(tree: ast.AST, *, module: str, attr: str) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Attribute):
            chain = []
            cur = fn
            while isinstance(cur, ast.Attribute):
                chain.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                chain.append(cur.id)
            # handle os.system, subprocess.run, subprocess.Popen
            if len(chain) >= 2 and chain[-1] == module and chain[0] == attr:
                return True
            if isinstance(fn.value, ast.Name) and fn.value.id == module and fn.attr == attr:
                return True
        if isinstance(fn, ast.Name) and fn.id == f"{module}_{attr}":
            # e.g. if aliased imports are normalized locally
            return True
    return False


def test_surface_does_not_import_forbidden_network_or_process_modules() -> None:
    root = Path(__file__).resolve().parents[1] / "src"
    files = [p for p in _iter_python_files(root / "zksec") if "__pycache__" not in p.parts]
    banned_modules = {"socket", "ssl", "urllib", "requests", "http", "subprocess", "asyncio"}

    offenders: list[str] = []
    for path in files:
        tree = ast.parse(path.read_text())
        if any(_contains_forbidden_import(tree, m) for m in banned_modules):
            offenders.append(str(path))

    assert not offenders, f"forbidden imports in source files: {offenders}"


def test_surface_does_not_call_forbidden_process_apis() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "zksec"
    files = [p for p in _iter_python_files(root) if "__pycache__" not in p.parts]

    offenders: list[str] = []
    for path in files:
        tree = ast.parse(path.read_text())
        for module, attr in (
            ("subprocess", "run"),
            ("subprocess", "Popen"),
            ("os", "system"),
            ("subprocess", "call"),
            ("socket", "socket"),
            ("socket", "create_connection"),
        ):
            if _contains_forbidden_call(tree, module=module, attr=attr):
                offenders.append(f"{path}:{module}.{attr}")

    assert not offenders, f"forbidden API calls in source files: {offenders}"
