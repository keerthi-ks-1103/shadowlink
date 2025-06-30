def generate_remediation(log: dict, risk: str) -> list:
    suggestions = []

    # MFA
    if str(log.get("success", "")).lower() == "false":
        suggestions.append("Check account for suspicious login patterns")

    if "finance" in log.get("resource", ""):
        suggestions.append("Enable strict access logging for finance modules")

    if log.get("action") == "upload":
        suggestions.append("Scan uploaded content for sensitive data leakage")

    if risk == "critical":
        suggestions.extend([
            "Immediate role audit recommended",
            "Apply stricter role-based access policies"
        ])
    elif risk == "high":
        suggestions.append("Review permissions for this user role")

    if not suggestions:
        suggestions.append("No critical issues detected")

    return list(set(suggestions))  # remove duplicates
