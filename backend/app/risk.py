SENSITIVITY = {"public":0, "internal":12, "confidential":28, "restricted":40}

def calculate_risk(approved, sensitivity, vendor_score=55, bytes_out=0):
    score, reasons = 0, []
    if not approved:
        score += 25
        reasons.append("Application is not approved (+25)")
    points = SENSITIVITY.get(sensitivity, 0)
    if points:
        score += points
        reasons.append(f"{sensitivity.title()} data sensitivity (+{points})")
    vendor_points = max(0, min(20, round((100-vendor_score)*0.2)))
    if vendor_points:
        score += vendor_points
        reasons.append(f"Vendor posture requires attention (+{vendor_points})")
    if bytes_out > 10000000:
        score += 15
        reasons.append("Large outbound transfer (+15)")
    elif bytes_out > 1000000:
        score += 7
        reasons.append("Elevated outbound transfer (+7)")
    score = min(100, score)
    level = "Critical" if score >= 80 else "High" if score >= 60 else "Moderate" if score >= 30 else "Low"
    return {"score":score, "level":level, "reasons":reasons}
