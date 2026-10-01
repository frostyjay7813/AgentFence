
import json, sys, time
sys.path.insert(0, sys.argv[1])
from agentfence.api import lambda_handler
def call(p,b=None):
    e={"httpMethod":"POST" if b is not None else "GET","path":p,"body":json.dumps(b) if b is not None else None}
    return json.loads(lambda_handler(e,None)["body"])
out={}
r=lambda_handler({"httpMethod":"GET","path":"/","body":None},None)
out["index"]={"status":r["statusCode"],"content_type":r["headers"]["Content-Type"],"bytes":len(r["body"])}
h=call("/health"); out["health"]={"status":h["status"],"gate":h["gate"]}
st=call("/api/state"); a=st["authorization"]; sc=st["scenario"]
v=call("/api/execute",{"request":sc,"authorization":a})
out["valid"]={"decision":v["decision"],"stage":v["stage"],"execution_status":v["receipt"]["execution_status"],
  "record":v["result"]["name"],"mrr":v["result"]["mrr"],"receipt_id":v["receipt"]["receipt_id"],
  "authorization_integrity":v["receipt"]["authorization_integrity"],"evidence_hash":v["receipt"]["integrity_hash"],
  "mode":v["mode"]}
out["attacks"]=[]
def atk(label,**kw):
    rq=dict(sc); rq.update(kw)
    d=call("/api/execute",{"request":rq,"authorization":a})
    out["attacks"].append({"attack":label,"decision":d["decision"],"reason":d["reason"],"stage":d["stage"],
                           "expected":d["expected"],"received":d["received"]})
atk("resource substitution",resource="customer/999")
atk("capability substitution",capability="customer.delete",action="delete")
atk("action substitution",action="delete")
atk("origin substitution",origin="CRM-B")
atk("task replay",task="TASK-185")
atk("agent substitution",agent="support-agent")
exp=call("/api/expire",{})["authorization"]
d=call("/api/execute",{"request":sc,"authorization":exp})
out["attacks"].append({"attack":"expired authorization","decision":d["decision"],"reason":d["reason"],"stage":d["stage"],"expected":d["expected"],"received":d["received"]})
tam=dict(a); tam["resource"]="customer/999"
d=call("/api/execute",{"request":sc,"authorization":tam})
out["attacks"].append({"attack":"tampered authorization","decision":d["decision"],"reason":d["reason"],"stage":d["stage"],"expected":d["expected"],"received":d["received"]})
d=call("/api/execute",{"request":sc,"authorization":None})
out["attacks"].append({"attack":"no authorization","decision":d["decision"],"reason":d["reason"],"stage":d["stage"],"expected":d["expected"],"received":d["received"]})
w=dict(sc,capability="customer.write",action="write")
wa=call("/api/authorize",w)["authorization"]
d=call("/api/execute",{"request":w,"authorization":wa})
out["approval_flow"]={"step1_no_approval":{"decision":d["decision"],"reason":d["reason"],"required":d["receipt"]["approval_required"]}}
ap=call("/api/approve",{"authorization":wa,"approver":"human.jay"})["approval"]
d2=call("/api/execute",{"request":w,"authorization":wa,"approval":ap})
out["approval_flow"]["step2_approved"]={"approval_id":ap["approval_id"],"approver":ap["approver"],
  "decision":d2["decision"],"execution_status":d2["receipt"]["execution_status"]}
d3=call("/api/execute",{"request":dict(w,task="TASK-185"),"authorization":wa,"approval":ap})
out["approval_flow"]["step3_replayed_other_task"]={"decision":d3["decision"],"reason":d3["reason"]}
print(json.dumps(out,indent=2))
