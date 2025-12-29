"""AST-based static code analyzer module.

Contains the StaticAnalyzer class, which uses an Abstract Syntax Tree
for more accurate vulnerability search and function argument analysis.
"""

import ast
import fnmatch
import sys

try:
    import tomllib
except ImportError:
    import tomli as tomllib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

from .vulnerabilities import FUNCTION_TO_CWE, SOURCES, Finding


class SecurityVisitor(ast.NodeVisitor):
    """AST visitor for finding potential vulnerabilities."""

    def __init__(
        self,
        file_path: Path,
        patterns_to_cwe: Dict[str, str],
        function_sinks: Optional[Dict[str, Set[str]]] = None,
        *,
        collect_only: bool = False,
        file_lines: Optional[List[str]] = None,
    ) -> None:
        """Initialize the visitor.

        Args:
            file_path: Path to the file being analyzed.
            patterns_to_cwe: Dictionary mapping patterns to CWE.
            function_sinks: Dictionary mapping function names to sink parameters.
            collect_only: If True, only collect information about function sinks.
            file_lines: List of lines in the file for checking inline comments.

        """
        self.file_path = file_path
        self.patterns_to_cwe = patterns_to_cwe
        self.findings: List[Finding] = []
        self.current_function: Optional[str] = None
        # Track tainted variables in current scope
        # Key: variable name, Value: source info
        self.tainted_vars: Dict[str, str] = {}
        # Track functions and their parameters that are passed to sinks
        # Key: function name, Value: Dict[param_name, Set[str]]
        self.function_sinks: Dict[str, Dict[str, Set[str]]] = function_sinks or {}
        self.collect_only = collect_only
        self.file_lines = file_lines or []
        self.imports: Dict[str, str] = {}

    def _should_ignore(self, line_number: int, cwe_id: Optional[str]) -> bool:
        """Check if a finding should be ignored based on inline comments."""
        if not self.file_lines or line_number > len(self.file_lines):
            return False

        line = self.file_lines[line_number - 1]
        if "# noqa" in line:
            comment_part = line.split("# noqa")[1].strip()
            if not comment_part or (
                comment_part.startswith(":") and (not cwe_id or cwe_id in comment_part)
            ):
                return True
            if not comment_part.startswith(":"):  # Just
                return True

        if "# astguard: ignore" in line:
            comment_part = line.split("# astguard: ignore")[1].strip()
            return not comment_part or bool(cwe_id and cwe_id in comment_part)
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Tracks the current function name."""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Tracks the current async function name."""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function

    def _get_full_name(self, node: ast.AST) -> Optional[str]:
        """Extract the full name of an attribute or function (e.g., os.system)."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = self._get_full_name(node.value)
            if prefix:
                return f"{prefix}.{node.attr}"
        return None

    def _resolve_full_name(self, node: ast.AST) -> Optional[str]:
        """Resolve the full name of a node, considering imports."""
        full_name = self._get_full_name(node)
        if not full_name:
            return None

        parts = full_name.split(".")
        base = parts[0]
        if base in self.imports:
            resolved_base = self.imports[base]
            return ".".join([resolved_base, *parts[1:]])
        return full_name

    def _is_safe_subprocess(self, node: ast.Call) -> bool:
        """Check if a subprocess call is safe (shell=False)."""
        is_shell = any(
            isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
            if kw.arg == "shell"
        )
        return not is_shell

    def _is_safe_execute(self, node: ast.Call) -> bool:
        """Check if an execute call is safe (uses a constant or non-string object)."""
        if not node.args:
            return True
        arg = node.args[0]
        # If it's a constant, it's safe (e.g., cursor.execute("SELECT 1"))
        if isinstance(arg, ast.Constant):
            return True
        # If it's a call, it might be an ORM query object builder (e.g., session.execute(select(...)))
        # ORM query objects are usually safer than raw strings
        if isinstance(arg, ast.Call):
            return True
        # For other types (names, binops, f-strings), we rely on taint analysis in _check_known_vulnerabilities
        return False

    def _is_safe_eval(self, node: ast.Call) -> bool:
        """Check if an eval/exec call is safe (uses a constant)."""
        return bool(node.args and isinstance(node.args[0], ast.Constant))

    def _is_tainted(self, node: ast.AST) -> bool:
        """Check if an AST node contains tainted data."""
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        if isinstance(node, ast.Call):
            full_call_name = self._resolve_full_name(node.func)
            if full_call_name and self._find_source_pattern(full_call_name):
                return True
            # Also check if it's a call to a function that returns tainted data
            # (not handled yet)
        if isinstance(node, ast.BinOp):
            return self._is_tainted(node.left) or self._is_tainted(node.right)
        if isinstance(node, ast.JoinedStr):
            return any(self._is_tainted(value) for value in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._is_tainted(node.value)
        return False

    def _find_source_pattern(self, full_call_name: str) -> Optional[str]:
        """Search for a matching source pattern."""
        for pattern in SOURCES:
            if (
                full_call_name == pattern
                or full_call_name.endswith(f".{pattern}")
                or full_call_name.startswith(f"{pattern}.")
            ):
                return pattern
        return None

    def _get_pattern_by_cwe(self, cwe_id: str, default: str) -> str:
        """Find a pattern name for a given CWE ID."""
        for pattern, cid in FUNCTION_TO_CWE.items():
            if cid == cwe_id:
                return pattern
        return default

    def _check_known_vulnerabilities(
        self, matched_pattern: str, node: ast.Call
    ) -> None:
        """Check if a call matching a known pattern is a vulnerability."""
        is_potentially_safe = self._is_call_potentially_safe(matched_pattern, node)
        has_tainted_args = any(self._is_tainted(arg) for arg in node.args)
        has_tainted_kwargs = any(self._is_tainted(kw.value) for kw in node.keywords)

        if (
            not is_potentially_safe or has_tainted_args or has_tainted_kwargs
        ) and not self.collect_only:
            cwe_id = self.patterns_to_cwe.get(matched_pattern)
            if not self._should_ignore(node.lineno, cwe_id):
                self.findings.append(
                    Finding(
                        str(self.file_path),
                        node.lineno,
                        matched_pattern,
                        self.current_function,
                    )
                )

        # Inter-procedural: check if arguments are parameters of current function
        if self.current_function:
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    if self.current_function not in self.function_sinks:
                        self.function_sinks[self.current_function] = {}

                    param_name = arg.id
                    if param_name not in self.function_sinks[self.current_function]:
                        self.function_sinks[self.current_function][param_name] = set()

                    cwe_id = self.patterns_to_cwe.get(matched_pattern)
                    if cwe_id:
                        self.function_sinks[self.current_function][param_name].add(
                            cwe_id
                        )

    def _check_interprocedural_sinks(
        self, full_call_name: str, node: ast.Call, matched_pattern: Optional[str]
    ) -> None:
        """Check if calling a function that has internal sinks with tainted data."""
        if self.collect_only or full_call_name not in self.function_sinks:
            return

        param_sinks = self.function_sinks[full_call_name]
        for _i, arg in enumerate(node.args):
            if self._is_tainted(arg):
                cwe_id = None
                for cwes in param_sinks.values():
                    if cwes:
                        cwe_id = next(iter(cwes))
                        break

                if not self._should_ignore(node.lineno, cwe_id):
                    self.findings.append(
                        Finding(
                            str(self.file_path),
                            node.lineno,
                            matched_pattern or full_call_name,
                            self.current_function,
                        )
                    )
                    if cwe_id and not self.findings[-1].cwe_details:
                        pattern = self._get_pattern_by_cwe(cwe_id, full_call_name)
                        self.findings[-1] = Finding(
                            str(self.file_path),
                            node.lineno,
                            pattern,
                            self.current_function,
                        )
                break

    def _check_keyword_patterns(self, node: ast.Call) -> None:
        """Check for special patterns in keyword arguments (e.g., debug=True)."""
        if self.collect_only:
            return

        for kw in node.keywords:
            pattern = f"{kw.arg}=True"
            if (
                pattern in self.patterns_to_cwe
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
            ):
                cwe_id = self.patterns_to_cwe.get(pattern)
                if not self._should_ignore(node.lineno, cwe_id):
                    self.findings.append(
                        Finding(
                            str(self.file_path),
                            node.lineno,
                            pattern,
                            self.current_function,
                        )
                    )

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls and their arguments."""
        full_call_name = self._resolve_full_name(node.func)

        if not full_call_name:
            self.generic_visit(node)
            return

        matched_pattern = self._find_matched_pattern(full_call_name)

        if matched_pattern:
            self._check_known_vulnerabilities(matched_pattern, node)

        self._check_interprocedural_sinks(full_call_name, node, matched_pattern)
        self._check_keyword_patterns(node)

        self.generic_visit(node)

    def _find_matched_pattern(self, full_call_name: str) -> Optional[str]:
        """Search for a suitable pattern for the call name."""
        for pattern in self.patterns_to_cwe:
            if (
                full_call_name == pattern
                or full_call_name.endswith(f".{pattern}")
                or full_call_name.startswith(f"{pattern}.")
            ):
                return pattern
        return None

    def _is_call_potentially_safe(self, matched_pattern: str, node: ast.Call) -> bool:
        """Check if the call is potentially safe."""
        if matched_pattern.startswith("subprocess."):
            return self._is_safe_subprocess(node)

        if matched_pattern == "os.system":
            return self._is_safe_execute(node)

        if matched_pattern == "execute":
            return self._is_safe_execute(node)

        if matched_pattern in ("eval", "exec", "compile"):
            return self._is_safe_eval(node)

        return False

    def visit_Assign(self, node: ast.Assign) -> None:
        """Analyzes assignments for hardcoded secrets and debug settings."""
        # Taint propagation
        is_val_tainted = self._is_tainted(node.value)

        for target in node.targets:
            target_names = self._get_target_names(target)

            for name in target_names:
                if is_val_tainted:
                    self.tainted_vars[name] = "tainted"
                elif name in self.tainted_vars:
                    # If reassigned to something safe, remove taint
                    del self.tainted_vars[name]

                if self.collect_only:
                    continue

                # Check for debug=True
                if (
                    name == "debug"
                    and "debug=True" in self.patterns_to_cwe
                    and isinstance(node.value, ast.Constant)
                    and node.value.value is True
                ):
                    cwe_id = self.patterns_to_cwe.get("debug=True")
                    if not self._should_ignore(node.lineno, cwe_id):
                        self.findings.append(
                            Finding(
                                str(self.file_path),
                                node.lineno,
                                "debug=True",
                                self.current_function,
                            )
                        )

                # Check for hardcoded secrets
                self._check_assign_for_secrets(name, node)

        self.generic_visit(node)

    def _get_target_names(self, target: ast.AST) -> list[str]:
        """Extract variable names from the left side of an assignment."""
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            return [elt.id for elt in target.elts if isinstance(elt, ast.Name)]
        return []

    def _check_assign_for_secrets(self, name: str, node: ast.Assign) -> None:
        """Check assignment for hardcoded secrets."""
        name_lower = name.lower()
        for secret_pattern in ["password", "secret", "token", "api_key"]:
            if (
                secret_pattern in name_lower
                and secret_pattern in self.patterns_to_cwe
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and node.value.value
            ):
                cwe_id = self.patterns_to_cwe.get(secret_pattern)
                if not self._should_ignore(node.lineno, cwe_id):
                    self.findings.append(
                        Finding(
                            str(self.file_path),
                            node.lineno,
                            secret_pattern,
                            self.current_function,
                        )
                    )

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Analyzes imports (some modules are dangerous by themselves)."""
        for alias in node.names:
            # Store import mapping
            local_name = alias.asname or alias.name
            self.imports[local_name] = alias.name

            if self.collect_only:
                continue

            if alias.name in self.patterns_to_cwe:
                cwe_id = self.patterns_to_cwe.get(alias.name)
                if not self._should_ignore(node.lineno, cwe_id):
                    self.findings.append(
                        Finding(
                            str(self.file_path),
                            node.lineno,
                            alias.name,
                            self.current_function,
                        )
                    )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Analyzes imports from modules."""
        if node.module:
            for alias in node.names:
                # Store import mapping: local_name -> module.remote_name
                local_name = alias.asname or alias.name
                self.imports[local_name] = f"{node.module}.{alias.name}"

        if self.collect_only:
            self.generic_visit(node)
            return

        if node.module and node.module in self.patterns_to_cwe:
            cwe_id = self.patterns_to_cwe.get(node.module)
            if not self._should_ignore(node.lineno, cwe_id):
                self.findings.append(
                    Finding(
                        str(self.file_path),
                        node.lineno,
                        node.module,
                        self.current_function,
                    )
                )
        self.generic_visit(node)


class StaticAnalyzer:
    """Class for performing static code analysis using AST."""

    def __init__(self) -> None:
        """Initialize the analyzer."""
        self._patterns_to_cwe = FUNCTION_TO_CWE

    def _match_path(self, file_path: Path, pattern: str) -> bool:
        """Match a file path against a pattern."""
        if not pattern:
            return False

        path_str = str(file_path).replace("\\", "/")
        pattern = pattern.replace("\\", "/")

        # If pattern has no slashes, match against any part of the path
        if "/" not in pattern:
            parts = path_str.split("/")
            return any(fnmatch.fnmatch(part, pattern) for part in parts)

        # If it has slashes, match against the whole path
        if fnmatch.fnmatch(path_str, pattern):
            return True

        # Also handle directory prefix match: "dir/" should match "dir/file.py"
        return bool(path_str.startswith(pattern.rstrip("/") + "/"))

    def analyze_file(
        self, file_path: Union[str, Path], config: Optional[Dict] = None
    ) -> List[Finding]:
        """Analyzes a Python file for dangerous patterns.

        Args:
            file_path: Path to the file for analysis.
            config: Optional configuration dictionary.

        Returns:
            List of discovered vulnerabilities.

        """
        path = Path(file_path)
        if path.suffix != ".py":
            return []

        if config is None:
            config = self._load_config(self._find_config_root(path))

        exclude_cwes = config.get("exclude", [])
        active_patterns = {
            pattern: cwe_id
            for pattern, cwe_id in self._patterns_to_cwe.items()
            if cwe_id not in exclude_cwes
        }

        try:
            content = path.read_text(encoding="utf-8")
            lines = content.splitlines()
            tree = ast.parse(content)

            # Single pass analysis
            visitor = SecurityVisitor(
                path,
                active_patterns,
                file_lines=lines,
            )
            visitor.visit(tree)
            # Sort findings by line number
            return sorted(visitor.findings, key=lambda x: x.line_number)
        except SyntaxError as e:
            print(f"Syntax error in file {path}: {e}", file=sys.stderr)
        except (OSError, UnicodeDecodeError) as e:
            print(f"Error reading file {path}: {e}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001
            print(f"Error analyzing file {path}: {e}", file=sys.stderr)

        return []

    def _collect_files_to_analyze(
        self, path: Path, include_patterns: List[str], ignore_patterns: List[str]
    ) -> List[Path]:
        """Collect all files to analyze based on include/ignore patterns."""
        files_to_analyze = []
        for file in path.rglob("*.py"):
            if not file.is_file():
                continue

            try:
                rel_file = file.relative_to(path)
            except ValueError:
                rel_file = file

            # Check for included files (if include list is not empty)
            if include_patterns and not any(
                self._match_path(rel_file, pattern) for pattern in include_patterns
            ):
                continue

            # Check for ignored files
            if any(self._match_path(rel_file, pattern) for pattern in ignore_patterns):
                continue

            files_to_analyze.append(file)
        return files_to_analyze

    def _collect_global_sinks(
        self, path: Path, files: List[Path], active_patterns: Dict
    ) -> Tuple[Dict, Dict]:
        """Collect function sinks from all files for inter-procedural analysis."""
        global_function_sinks = {}
        file_cache = {}
        for file in files:
            try:
                content = file.read_text(encoding="utf-8")
                lines = content.splitlines()
                tree = ast.parse(content)
                file_cache[file] = (lines, tree)

                collector = SecurityVisitor(
                    file, active_patterns, collect_only=True, file_lines=lines
                )
                collector.visit(tree)

                # Register sinks with both short and qualified names
                rel_path = file.relative_to(path)
                if rel_path.name == "__init__.py":
                    module_parts = rel_path.parent.parts
                else:
                    module_parts = rel_path.with_suffix("").parts
                module_name = ".".join(module_parts)

                for func_name, sinks in collector.function_sinks.items():
                    # Short name for calls within the same module
                    if func_name not in global_function_sinks:
                        global_function_sinks[func_name] = {}
                    global_function_sinks[func_name].update(sinks)

                    # Qualified name for calls from other modules
                    if module_name:
                        q_name = f"{module_name}.{func_name}"
                        if q_name not in global_function_sinks:
                            global_function_sinks[q_name] = {}
                        global_function_sinks[q_name].update(sinks)

            except Exception as e:  # noqa: BLE001
                print(f"Error during collection in {file}: {e}", file=sys.stderr)
        return global_function_sinks, file_cache

    def analyze_directory(self, directory_path: Union[str, Path]) -> List[Finding]:
        """Recursively analyze all Python files in a directory.

        Args:
            directory_path: Path to the directory for analysis.

        Returns:
            List of discovered vulnerabilities.

        """
        all_findings = []
        path = Path(directory_path)
        config = self._load_config(self._find_config_root(path))

        files_to_analyze = self._collect_files_to_analyze(
            path, config.get("include", []), config.get("ignore", [])
        )

        # Prepare patterns once for all files in directory
        exclude_cwes = config.get("exclude", [])
        active_patterns = {
            pattern: cwe_id
            for pattern, cwe_id in self._patterns_to_cwe.items()
            if cwe_id not in exclude_cwes
        }

        # Pass 1: Global collection of function sinks and caching
        global_function_sinks, file_cache = self._collect_global_sinks(
            path, files_to_analyze, active_patterns
        )

        # Pass 2: Actual analysis
        for file in files_to_analyze:
            if file not in file_cache:
                continue
            try:
                lines, tree = file_cache[file]
                visitor = SecurityVisitor(
                    file,
                    active_patterns,
                    function_sinks=global_function_sinks,
                    file_lines=lines,
                )
                visitor.visit(tree)
                all_findings.extend(visitor.findings)
            except Exception as e:  # noqa: BLE001
                print(f"Error during analysis in {file}: {e}", file=sys.stderr)

        return sorted(all_findings, key=lambda x: (x.file_path, x.line_number))

    def _find_config_root(self, path: Path) -> Path:
        """Search for a configuration file upwards from the given path."""
        current = path.absolute()
        # If path is a file, start from its parent
        if current.is_file():
            current = current.parent

        for parent in [current, *current.parents]:
            if (parent / "pyproject.toml").exists() or (
                parent / ".astguardignore"
            ).exists():
                return parent
        return current

    def _load_config(self, root_path: Path) -> dict:
        """Load configuration from .astguardignore and pyproject.toml."""
        config = {"ignore": [], "include": [], "exclude": []}

        # Load .astguardignore
        ignore_file = root_path / ".astguardignore"
        if ignore_file.exists():
            try:
                patterns = [
                    line.strip()
                    for line in ignore_file.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.startswith("#")
                ]
                config["ignore"].extend(patterns)
            except Exception as e:  # noqa: BLE001
                print(f"Error reading {ignore_file}: {e}", file=sys.stderr)

        # Load pyproject.toml
        pyproject_file = root_path / "pyproject.toml"
        if pyproject_file.exists():
            try:
                with pyproject_file.open("rb") as f: # astguard: ignore CWE-22
                    data = tomllib.load(f)
                    astguard_config = data.get("tool", {}).get("astguard", {})

                    # Handle include (always files)
                    config["include"].extend(astguard_config.get("include", []))

                    # Smartly distribute items from 'ignore' and 'exclude'
                    # We support both for backward compatibility and better naming
                    raw_ignore = astguard_config.get("ignore", [])
                    raw_exclude = astguard_config.get("exclude", [])

                    for item in raw_ignore + raw_exclude:
                        if isinstance(item, str) and item.startswith("CWE-"):
                            if item not in config["exclude"]:
                                config["exclude"].append(item)
                        elif item not in config["ignore"]:
                            config["ignore"].append(item)
            except Exception as e:  # noqa: BLE001
                print(f"Error reading {pyproject_file}: {e}", file=sys.stderr)

        return config

    def run_analysis(self, path: Union[str, Path]) -> List[Finding]:
        """Start the analysis process for the specified path.

        Args:
            path: Path to a file or directory.

        Returns:
            List of discovered vulnerabilities.

        """
        p = Path(path)
        if p.is_file():
            return self.analyze_file(p)
        if p.is_dir():
            return self.analyze_directory(p)

        return []
