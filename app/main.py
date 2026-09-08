import os, hmac, hashlib, logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import PlainTextResponse, JSONResponse
import httpx
from openai import OpenAI

logging.basicConfig(level=logging.INFO)
log=logging.getLogger("wa-ai")
app=FastAPI(title="AI Command Center")
VERIFY_TOKEN=os.getenv("WHATSAPP_VERIFY_TOKEN","")
WA_TOKEN=os.getenv("WHATSAPP_TOKEN","")
PHONE_ID=os.getenv("WHATSAPP_PHONE_NUMBER_ID","")
APP_SECRET=os.getenv("WHATSAPP_APP_SECRET","")
OWNER="".join(c for c in os.getenv("OWNER_PHONE","") if c.isdigit())
MODEL=os.getenv("OPENAI_MODEL_SMART") or os.getenv("OPENAI_MODEL","gpt-5.6-sol")
REASONING=os.getenv("OPENAI_REASONING","high")
GRAPH=os.getenv("WHATSAPP_GRAPH_VERSION","v23.0")
client=OpenAI(api_key=os.getenv("OPENAI_API_KEY")) if os.getenv("OPENAI_API_KEY") else None
seen=set()

@app.get("/health")
def health():
    return {"ok":True,"service":"whatsapp-ai-command-center","model":MODEL,"ai_configured":bool(client),"whatsapp_configured":bool(WA_TOKEN and PHONE_ID),"owner_configured":bool(OWNER)}

@app.get("/webhook",response_class=PlainTextResponse)
def verify_webhook(hub_mode:str|None=None,hub_verify_token:str|None=None,hub_challenge:str|None=None):
    # FastAPI converts underscores, Meta sends hub.mode/hub.verify_token/hub.challenge; parse manually in middleware route below is safer.
    raise HTTPException(400,"Use Meta query parameters")

@app.api_route("/webhook",methods=["GET"],include_in_schema=False)
async def verify_meta(request:Request):
    q=request.query_params
    if q.get("hub.mode")=="subscribe" and VERIFY_TOKEN and hmac.compare_digest(q.get("hub.verify_token",""),VERIFY_TOKEN):
        return PlainTextResponse(q.get("hub.challenge",""))
    raise HTTPException(403,"Webhook verification failed")

def signature_ok(body:bytes,sig:str):
    if not APP_SECRET: return True
    if not sig.startswith("sha256="): return False
    expected=hmac.new(APP_SECRET.encode(),body,hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig[7:],expected)

async def send_text(to:str,text:str):
    if not (WA_TOKEN and PHONE_ID):
        log.warning("WhatsApp credentials missing; reply not sent")
        return
    url=f"https://graph.facebook.com/{GRAPH}/{PHONE_ID}/messages"
    headers={"Authorization":f"Bearer {WA_TOKEN}","Content-Type":"application/json"}
    payload={"messaging_product":"whatsapp","to":to,"type":"text","text":{"body":text[:4096]}}
    async with httpx.AsyncClient(timeout=30) as hc:
        r=await hc.post(url,headers=headers,json=payload); r.raise_for_status()

async def answer(text:str):
    if not client: return "AI is connected to the webhook, but the OpenAI API key is not configured yet."
    prompt="You are the owner's private AI Command Center on WhatsApp. Accuracy is more important than speed. Be concise but verify assumptions. Never claim an external action succeeded unless a connected tool actually executed it. For consequential actions, explain the intended action and require explicit confirmation before execution."
    try:
        r=client.responses.create(model=MODEL,reasoning={"effort":REASONING},instructions=prompt,input=text)
        return r.output_text or "I couldn't produce a reliable answer."
    except Exception:
        log.exception("OpenAI failure")
        return "I couldn't process that reliably, so no external action was performed."

@app.post("/webhook")
async def receive(request:Request):
    body=await request.body()
    if not signature_ok(body,request.headers.get("x-hub-signature-256","")):
        raise HTTPException(401,"Invalid signature")
    data=await request.json()
    try:
        for entry in data.get("entry",[]):
            for change in entry.get("changes",[]):
                value=change.get("value",{})
                for msg in value.get("messages",[]) or []:
                    mid=msg.get("id")
                    if not mid or mid in seen: continue
                    seen.add(mid)
                    sender="".join(c for c in msg.get("from","") if c.isdigit())
                    if OWNER and sender!=OWNER:
                        log.warning("Ignored unauthorized sender")
                        continue
                    if msg.get("type")!="text":
                        await send_text(sender,"I received the message. Text commands are enabled first; voice and image processing will be enabled after the core production test.")
                        continue
                    text=msg.get("text",{}).get("body","").strip()
                    if text: await send_text(sender,await answer(text))
    except Exception:
        log.exception("Webhook processing error")
    return JSONResponse({"ok":True})
