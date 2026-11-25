import ast
import operator
import re

from app.security.models import AttackType, InspectionLocation, RuleMatch, Severity
from app.security.rules.base import BaseRule, RegexRule, clean_evidence

_SAFE_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _safe_eval_arithmetic(expr_str: str) -> float | None:
    """Safely evaluates constant arithmetic expressions without eval(). O(len(s))."""
    try:
        clean = expr_str.strip()
        # Must only contain digits, spaces, parentheses and arithmetic operators
        if not re.match(r"^[\d\s+\-*/()]+$", clean):
            return None
        parsed = ast.parse(clean, mode="eval")

        def _eval_node(node):
            if isinstance(node, ast.Expression):
                return _eval_node(node.body)
            elif isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                return float(node.value)
            elif isinstance(node, ast.BinOp) and type(node.op) in _SAFE_OPS:
                left = _eval_node(node.left)
                right = _eval_node(node.right)
                if left is None or right is None:
                    return None
                if isinstance(node.op, ast.Div) and right == 0:
                    return None
                return _SAFE_OPS[type(node.op)](left, right)
            elif isinstance(node, ast.UnaryOp) and type(node.op) in _SAFE_OPS:
                val = _eval_node(node.operand)
                return _SAFE_OPS[type(node.op)](val) if val is not None else None
            return None

        return _eval_node(parsed)
    except Exception:
        return None


_UNQUOTED_ARITHMETIC_RE = re.compile(
    r"""(?i)(?:^|[\s,;(\'\"]|\b\d+\b)\s*(?:OR|AND)\s+"""
    r"""([0-9\s+\-*\/]+?)\s*(>=|<=|!=|<>|=|>|<|\bLIKE\b)\s*([0-9\s+\-*\/]+?)"""
    r"""(?=[\s,;)\'\"]|--|#|/\*|$)""",
    re.IGNORECASE,
)

_UNQUOTED_BETWEEN_RE = re.compile(
    r"(?i)(?:^|[\s,;(\'\"]|\b\d+\b)\s*(?:OR|AND)\s+([0-9\s+\-*\/()]+?)\s+(\bNOT\s+BETWEEN\b|\bBETWEEN\b)\s+([0-9\s+\-*\/()]+?)\s+AND\s+([0-9\s+\-*\/()]+?)(?=[\s,;)\'\"]|--|#|/\*|$)",
    re.IGNORECASE,
)

_TSQL_WAITFOR_RE = re.compile(
    r"""(?i)\bWAITFOR\s+(?:DELAY|TIME)\s+[\'\"0-9\:]+""",
    re.IGNORECASE,
)


class UnquotedArithmeticTautologyRule(BaseRule):
    """Detects unquoted logical/arithmetic/BETWEEN tautologies and T-SQL time-delay injection (SQLI-006)."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="SQLI-006",
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="Unquoted Logical/Arithmetic Tautology and Time-Delay SQLi",
            rationale=(
                "Detects blind unquoted arithmetic, relational, and BETWEEN/NOT BETWEEN "
                "tautologies (e.g. 105 OR 17-7=10, 105 OR 17-7 BETWEEN 10 AND 10) "
                "and T-SQL time-delay commands (WAITFOR DELAY/TIME) bypassing standard filters."
            ),
        )

    def evaluate(
        self,
        input_text: str,
        location: InspectionLocation,
        location_key: str | None = None,
    ) -> RuleMatch | None:
        if not input_text:
            return None

        # 1. Check T-SQL time-delay
        waitfor_m = _TSQL_WAITFOR_RE.search(input_text)
        if waitfor_m:
            return RuleMatch(
                rule_id=self.rule_id,
                attack_type=self.attack_type,
                severity=self.severity,
                confidence=self.confidence,
                location=location,
                location_key=location_key,
                evidence=clean_evidence(waitfor_m.group(0)),
                description=f"{self.description} (Time-Delay Pattern)",
            )

        # 2. Check unquoted BETWEEN / NOT BETWEEN arithmetic tautology (O(n) fast-guard + safe AST eval)
        lower_text = input_text.lower()
        if "between" in lower_text and "and" in lower_text:
            for between_m in _UNQUOTED_BETWEEN_RE.finditer(input_text):
                e_val, op, e_lo, e_hi = between_m.groups()
                v_expr = _safe_eval_arithmetic(e_val)
                v_lo = _safe_eval_arithmetic(e_lo)
                v_hi = _safe_eval_arithmetic(e_hi)
                if v_expr is not None and v_lo is not None and v_hi is not None:
                    op_clean = " ".join(op.split()).upper()
                    lo_bound = min(v_lo, v_hi)
                    hi_bound = max(v_lo, v_hi)
                    if op_clean == "BETWEEN":
                        is_tautology = lo_bound - 1e-5 <= v_expr <= hi_bound + 1e-5
                    elif op_clean == "NOT BETWEEN":
                        is_tautology = v_expr < lo_bound - 1e-5 or v_expr > hi_bound + 1e-5
                    else:
                        is_tautology = False

                    if is_tautology:
                        return RuleMatch(
                            rule_id=self.rule_id,
                            attack_type=self.attack_type,
                            severity=self.severity,
                            confidence=0.98,
                            location=location,
                            location_key=location_key,
                            evidence=clean_evidence(between_m.group(0)),
                            description=(
                                f"{self.description} "
                                f"(Between Tautology: {e_val.strip()} {op_clean} {e_lo.strip()} AND {e_hi.strip()})"
                            ),
                        )

        # 3. Check unquoted arithmetic and relational tautology
        for match in _UNQUOTED_ARITHMETIC_RE.finditer(input_text):
            e1, op, e2 = match.groups()
            v1 = _safe_eval_arithmetic(e1)
            v2 = _safe_eval_arithmetic(e2)
            op_clean = op.strip().upper()

            if op_clean in (">", "<", ">=", "<="):
                if v1 is None or v2 is None:
                    continue
                if op_clean == ">":
                    is_tautology = v1 > v2
                elif op_clean == ">=":
                    is_tautology = v1 >= v2 - 1e-5
                elif op_clean == "<":
                    is_tautology = v1 < v2
                else:
                    is_tautology = v1 <= v2 + 1e-5

                has_arith_op = any(op_ch in expr for expr in (e1, e2) for op_ch in "+-*/")
                if not (is_tautology and (has_arith_op or abs(v1 - v2) < 1e-5)):
                    continue
                conf = 0.98
            else:
                is_tautology = False
                if v1 is not None and v2 is not None:
                    if op_clean in ("=", "LIKE"):
                        is_tautology = abs(v1 - v2) < 1e-5
                    elif op_clean in ("!=", "<>"):
                        is_tautology = abs(v1 - v2) >= 1e-5
                    else:
                        is_tautology = True
                else:
                    # Still a structured boolean arithmetic injection probe
                    is_tautology = True
                conf = 0.98 if is_tautology else 0.90

            return RuleMatch(
                rule_id=self.rule_id,
                attack_type=self.attack_type,
                severity=self.severity,
                confidence=conf,
                location=location,
                location_key=location_key,
                evidence=clean_evidence(match.group(0)),
                description=f"{self.description} (Arithmetic Tautology: {e1} {op} {e2})",
            )

        return None


def get_sqli_rules() -> list[BaseRule]:
    """Returns the deterministic SQL Injection rule collection."""
    return [
        RegexRule(
            rule_id="SQLI-001",
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="Boolean-based SQL Injection Tautology",
            rationale=(
                "Detects logical OR/AND tautologies commonly used to bypass authentication "
                "(e.g. ' OR '1'='1)."
            ),
            pattern=r"""(?i)(?:\b(?:or|and)\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+[\'\"]?|\b(?:or|and)\s+\d+\s*=\s*\d+)""",
        ),
        RegexRule(
            rule_id="SQLI-002",
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="UNION-based SQL Injection",
            rationale=(
                "Detects UNION SELECT statements designed to exfiltrate "
                "unauthorized database rows."
            ),
            pattern=r"""(?i)\bunion\s+(?:all\s+|distinct\s+)?select\b""",
        ),
        RegexRule(
            rule_id="SQLI-003",
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.HIGH,
            confidence=0.90,
            description="SQL Comment Syntax Termination",
            rationale=(
                "Detects trailing quote characters coupled with "
                "SQL comment indicators (-- , /*, #)."
            ),
            pattern=r"""(?i)(?:[\'\"`]\s*(?:--|#|/\*)|/\*!\d+.*?(\*/|$))""",
        ),
        RegexRule(
            rule_id="SQLI-004",
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.HIGH,
            confidence=0.90,
            description="Database Enumeration and Fingerprinting Function Abuse",
            rationale=(
                "Detects dangerous SQL functions such as sleep(), benchmark(), database(), "
                "schema(), load_file(), waitfor delay/time or into outfile."
            ),
            pattern=r"""(?i)\b(?:sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+|version\s*\(\s*\)|database\s*\(\s*\)|schema\s*\(\s*\)|load_file\s*\(|into\s+(?:outfile|dumpfile)|waitfor\s+(?:delay|time)\b)""",
        ),
        RegexRule(
            rule_id="SQLI-005",
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence=0.90,
            description="Stacked Query and Destructive SQL DDL/DML",
            rationale=(
                "Detects semicolon-terminated stacked statements executing "
                "DROP, TRUNCATE, DELETE, or ALTER."
            ),
            pattern=r"""(?i);\s*(?:drop\s+table|drop\s+database|truncate\s+table|alter\s+table|insert\s+into|update\s+\w+\s+set|delete\s+from)\b""",
        ),
        UnquotedArithmeticTautologyRule(),
        RegexRule(
            rule_id="SQLI-007",
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="Obfuscated Scientific-Float, CHAR Concatenation, and Subquery Fingerprinting SQLi",
            rationale=(
                "Detects scientific-notation keyword concatenation (1e0UNION, 9e0OR), "
                "quote-free multi-byte CHAR()/CHR() obfuscation, and embedded SELECT CASE/version probes."
            ),
            pattern=(
                r"""(?i)(?:\b\d+(?:\.\d+)?e[+-]?\d+(?:union|select|or|and|where|from|having|order|group)\b"""
                r"""|\b(?:CHAR|CHR)\s*\(\s*\d+(?:\s*,\s*\d+){3,}\s*\)"""
                r"""|\(\s*select\s+(?:case\s+when\b|sqlite_version\s*\(|@@version\b|current_user\b))"""
            ),
        ),
    ]
