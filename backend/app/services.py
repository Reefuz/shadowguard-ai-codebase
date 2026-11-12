import json, re
from .database import connection
from .risk import calculate_risk

def ingest_event(event):
    with connection() as conn:
        app = conn.execute("SELECT id,name,approved,vendor_score FROM shadow_apps WHERE %s = ANY(domains) LIMIT 1", (event.domain,)).fetchone()
        if app is None:
            app = conn.execute("INSERT INTO shadow_apps (name,vendor_name,domains,approved,category,vendor_score,risk_score,risk_level,last_seen) VALUES (%s,%s,ARRAY[%s],FALSE,'Unclassified',45,55,'Moderate',NOW()) ON CONFLICT(name) DO UPDATE SET last_seen=NOW() RETURNING id,name,approved,vendor_score", (event.domain.split('.')[0].title(),"Unclassified",event.domain)).fetchone()
        else:
            conn.execute("UPDATE shadow_apps SET last_seen=NOW() WHERE id=%s",(app["id"],))
        risk=calculate_risk(app["approved"],event.data_sensitivity.value,app["vendor_score"],event.bytes_out)
        conn.execute("INSERT INTO telemetry_events (app_id,domain,user_id,department,event_type,data_sensitivity,bytes_out,occurred_at,source,risk_score) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(app["id"],event.domain,event.user_id,event.department,event.event_type.value,event.data_sensitivity.value,event.bytes_out,event.occurred_at,event.source,risk["score"]))
        conn.execute("UPDATE shadow_apps SET risk_score=GREATEST(risk_score,%s),risk_level=%s WHERE id=%s",(risk["score"],risk["level"],app["id"]))
        incident=None
        if event.data_sensitivity.value in ("confidential","restricted") or risk["score"]>=60:
            incident=conn.execute("INSERT INTO incidents (app_id,title,severity,status,description,risk_score,detected_at) VALUES (%s,%s,%s,'Open',%s,%s,%s) RETURNING id",(app["id"],f"Potential data exposure via {app['name']}",risk["level"],f"{event.data_sensitivity.value} data observed for {event.user_id} in {event.department}.",risk["score"],event.occurred_at)).fetchone()
        conn.execute("INSERT INTO audit_logs (actor,action,entity_type,details) VALUES (%s,'telemetry.ingested','telemetry',%s::jsonb)",(event.user_id,json.dumps({"domain":event.domain,"risk_score":risk["score"]})))
        return {"app_id":app["id"],"app_name":app["name"],"risk_score":risk["score"],"risk_level":risk["level"],"risk_reasons":risk["reasons"],"incident_id":incident["id"] if incident else None}

RULES=[
("data_sharing",r"share.{0,80}(third part|partner|affiliate)"),
("model_training",r"(train|improve).{0,80}(model|artificial intelligence|ai)"),
("retention",r"(retain|retention|delete).{0,80}(data|information)"),
("encryption",r"(encrypt|encryption|tls|at rest)"),
("breach_notice",r"(breach|incident).{0,100}(notify|notification|hours|days)"),
("data_residency",r"(region|country|residency|transfer).{0,80}(data|personal)")]

def analyze_policy(vendor, policy):
    text=re.sub(r"\s+"," ",policy).lower()
    findings=[]
    for name,pattern in RULES:
        match=re.search(pattern,text)
        findings.append({"clause":name,"found":bool(match),"evidence_excerpt":text[max(0,match.start()-80):min(len(text),match.end()+120)] if match else None})
    flags=sum(1 for f in findings if not f["found"] or f["clause"] in ("data_sharing","model_training"))
    score=min(100,20+flags*12)
    return {"vendor_name":vendor,"analysis_type":"heuristic_simulation","risk_score":score,"risk_level":"High" if score>=60 else "Moderate" if score>=35 else "Low","disclaimer":"Keyword simulation only; human validation required.","findings":findings}
