import hmac, json
from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .config import settings
from .database import connection, fetch_all, fetch_one, DatabaseUnavailable
from .models import TelemetryEvent, PolicyRequest, RemediationRequest
from .services import ingest_event, analyze_policy

app=FastAPI(title="ShadowGuard AI API",version="1.0.0",docs_url=None if settings.disable_docs else "/docs",redoc_url=None if settings.disable_docs else "/redoc",openapi_url=None if settings.disable_docs else "/openapi.json")
app.add_middleware(CORSMiddleware,allow_origins=list(settings.cors_origins),allow_credentials=False,allow_methods=["GET","POST"],allow_headers=["Content-Type","X-API-Key"])

@app.middleware("http")
async def security_headers(request,call_next):
    response=await call_next(request)
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Referrer-Policy"]="no-referrer"
    response.headers["Cache-Control"]="no-store"
    return response

def auth(x_api_key:str|None=Header(default=None,alias="X-API-Key")):
    if not settings.api_key: raise HTTPException(503,"Service authentication is not configured")
    if not x_api_key or not hmac.compare_digest(x_api_key,settings.api_key): raise HTTPException(401,"Invalid API key")

def safe_db(fn):
    try: return fn()
    except DatabaseUnavailable as exc: raise HTTPException(503,str(exc))
    except Exception: raise HTTPException(500,"Database operation failed")

@app.get("/api/v1/health")
def health(): return {"status":"ok","service":"shadowguard-api","environment":settings.environment}

@app.get("/api/v1/dashboard",dependencies=[Depends(auth)])
def dashboard():
    def run():
        metrics=fetch_one("SELECT (SELECT COUNT(*) FROM shadow_apps)::int total_apps,(SELECT COUNT(*) FROM incidents WHERE status IN ('Open','Investigating'))::int active_incidents,COALESCE((SELECT ROUND(AVG(risk_score)) FROM shadow_apps),0)::int exposure_index,(SELECT COUNT(*) FROM remediation_logs WHERE created_at>=NOW()-INTERVAL '30 days')::int remediations")
        distribution=fetch_all("SELECT risk_level name,COUNT(*)::int value FROM shadow_apps GROUP BY risk_level ORDER BY CASE risk_level WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Moderate' THEN 3 ELSE 4 END")
        trend=fetch_all("SELECT TO_CHAR(day,'Mon DD') day,COALESCE(ROUND(AVG(t.risk_score)),0)::int exposure FROM generate_series(CURRENT_DATE-INTERVAL '6 days',CURRENT_DATE,INTERVAL '1 day') day LEFT JOIN telemetry_events t ON DATE(t.occurred_at)=DATE(day) GROUP BY day ORDER BY day")
        recent=fetch_all("SELECT id,title,severity,status,detected_at FROM incidents ORDER BY detected_at DESC LIMIT 6")
        return {"metrics":metrics,"distribution":distribution,"trend":trend,"recent_incidents":recent}
    return safe_db(run)

@app.get("/api/v1/apps",dependencies=[Depends(auth)])
def apps(): return safe_db(lambda:fetch_all("SELECT id,name,vendor_name,domains,approved,category,vendor_score,risk_score,risk_level,last_seen FROM shadow_apps ORDER BY risk_score DESC,last_seen DESC"))

@app.get("/api/v1/incidents",dependencies=[Depends(auth)])
def incidents(): return safe_db(lambda:fetch_all("SELECT i.id,i.title,i.severity,i.status,i.description,i.risk_score,i.detected_at,a.name app_name FROM incidents i LEFT JOIN shadow_apps a ON a.id=i.app_id ORDER BY i.detected_at DESC LIMIT 100"))

@app.post("/api/v1/telemetry/ingest",dependencies=[Depends(auth)])
def ingest(event:TelemetryEvent): return safe_db(lambda:ingest_event(event))

@app.post("/api/v1/policies/analyze",dependencies=[Depends(auth)])
def policy(payload:PolicyRequest):
    result=analyze_policy(payload.vendor_name,payload.policy_text)
    def save():
        with connection() as conn:
            conn.execute("INSERT INTO policy_assessments (vendor_name,risk_score,risk_level,findings,analysis_type) VALUES (%s,%s,%s,%s::jsonb,%s)",(result["vendor_name"],result["risk_score"],result["risk_level"],json.dumps(result["findings"]),result["analysis_type"]))
        return result
    return safe_db(save)

@app.post("/api/v1/incidents/{incident_id}/remediate",dependencies=[Depends(auth)])
def remediate(incident_id:int,payload:RemediationRequest):
    def save():
        with connection() as conn:
            incident=conn.execute("SELECT id FROM incidents WHERE id=%s",(incident_id,)).fetchone()
            if not incident: raise HTTPException(404,"Incident not found")
            row=conn.execute("INSERT INTO remediation_logs (incident_id,action,approved_by,status) VALUES (%s,%s,%s,'Pending approval') RETURNING id,incident_id,action,approved_by,status,created_at",(incident_id,payload.action,payload.approved_by)).fetchone()
            conn.execute("INSERT INTO audit_logs (actor,action,entity_type,entity_id,details) VALUES (%s,'remediation.proposed','incident',%s,%s::jsonb)",(payload.approved_by,str(incident_id),json.dumps({"remediation_id":row["id"]})))
            return row
    try: return save()
    except HTTPException: raise
    except Exception: raise HTTPException(500,"Database operation failed")
