"""
NetMon – network session firewall management server.

Starts FastAPI web UI + MQTT subscriber.
"""

import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DBSession

from server import config, mqtt_subscriber
from server.database import get_db, init_db, Session, Host, FirewallRule
from server.routers import sessions as sessions_router
from server.routers import rules as rules_router
from fastapi import FastAPI

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    mqtt_subscriber.start()
    yield
    mqtt_subscriber.stop()


app = FastAPI(title="NetMon", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="server/static"), name="static")
templates = Jinja2Templates(directory="server/templates")

app.include_router(sessions_router.router)
app.include_router(rules_router.router)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: DBSession = Depends(get_db)):
    total_sessions  = db.query(Session).count()
    pending         = db.query(Session).filter(Session.review_status == "pending").count()
    approved        = db.query(Session).filter(Session.review_status == "approved").count()
    denied          = db.query(Session).filter(Session.review_status == "denied").count()
    deployed_rules  = db.query(FirewallRule).filter(FirewallRule.status == "deployed").count()
    pending_rules   = db.query(FirewallRule).filter(FirewallRule.status == "deploying").count()
    hosts           = db.query(Host).order_by(Host.last_seen.desc()).all()
    recent_sessions = db.query(Session).order_by(Session.last_seen.desc()).limit(10).all()
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "total_sessions": total_sessions,
        "pending": pending,
        "approved": approved,
        "denied": denied,
        "deployed_rules": deployed_rules,
        "pending_rules": pending_rules,
        "hosts": hosts,
        "recent_sessions": recent_sessions,
    })


if __name__ == "__main__":
    uvicorn.run("server.main:app", host=config.WEB_HOST, port=config.WEB_PORT,
                reload=False, log_level="info")
