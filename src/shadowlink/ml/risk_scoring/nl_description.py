def generate_description(log: dict, risk: str) -> str:
    role = log.get("role", "unknown role")
    action = log.get("action", "unknown action")
    resource = log.get("resource", "unknown resource")
    success = log.get("success", False)

    base = f"The user with role '{role}' attempted to perform '{action}' on resource '{resource}'."
    base += " The action succeeded." if success else " The action failed."

    if risk == "high":
        return base + " This behavior indicates a high-risk activity with potential for serious security impact."
    elif risk == "medium":
        return base + " This action is moderately risky and may require further monitoring."
    else:
        return base + " This is a low-risk activity."
