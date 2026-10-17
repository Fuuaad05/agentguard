import ast
import json
import sys


def verify_code(source):
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        return {
            "status": "error",
            "message": f"Invalid Python syntax at line {error.lineno}",
            "evidence": []
        }

    evidence = []
    seen = set()

    def add(category, line, description):
        key = (category, line)
        if key not in seen:
            seen.add(key)
            evidence.append({
                "category": category,
                "line": line,
                "description": description,
                "status": "pattern_confirmed"
            })

    for node in ast.walk(tree):

        # 1. Detect direct calls to eval()
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "eval"
            ):
                add(
                    "CWE-94",
                    node.lineno,
                    "Direct call to Python eval() found."
                )

        # 2. Detect SQL queries constructed using f-strings
        if isinstance(node, ast.JoinedStr):
            text = ast.get_source_segment(source, node) or ""
            if any(word in text.upper() for word in (
                "SELECT", "INSERT", "UPDATE", "DELETE"
            )):
                add(
                    "CWE-89",
                    node.lineno,
                    "SQL statement constructed using an f-string."
                )

        # 3. Detect SQL queries constructed with string concatenation
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            text = ast.get_source_segment(source, node) or ""
            if any(word in text.upper() for word in (
                "SELECT", "INSERT", "UPDATE", "DELETE"
            )):
                add(
                    "CWE-89",
                    node.lineno,
                    "Possible SQL query construction using concatenation."
                )

        # 4. Detect hardcoded password comparisons
        if isinstance(node, ast.Compare):
            text = ast.get_source_segment(source, node) or ""
            if "password" in text.lower():
                if any(
                    isinstance(part, ast.Constant)
                    and isinstance(part.value, str)
                    for part in [node.left, *node.comparators]
                ):
                    add(
                        "CWE-798",
                        node.lineno,
                        "Password comparison against a hardcoded string."
                    )

    return {
        "status": "completed",
        "evidence": evidence,
        "total": len(evidence)
    }


if __name__ == "__main__":
    source = sys.stdin.read()
    print(json.dumps(verify_code(source)))
