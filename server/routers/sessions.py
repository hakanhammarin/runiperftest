"""
Session review API + HTML views.
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DBSession

from server.database import get_db, Session, FirewallRule, Host
from server import mqtt_subscriber

router = APIRouter()
templates = Jinja2Templates(directory="server/templates")


@router.get("/sessions", response_class=HTMLResponse)
def list_sessions(request: Request, status: str = "pending", db: DBSession = Depends(get_db)):
    q = db.query(Session)
    if status != "all":
        q = q.filter(Session.review_status == status)
    sessions = q.order_by(Session.last_seen.desc()).limit(500).all()
    hosts = {h.hostname: h for h in db.query(Host).all()}
    return templates.TemplateResponse("sessions.html", {
        "request": request,
        "sessions": sessions,
        "hosts": hosts,
        "current_status": status,
    })


@router.post("/sessions/{session_id}/approve")
def approve_session(session_id: int, request: Request,
                    action: str = Form("allow"),
                    direction: str = Form("out"),
                    db: DBSession = Depends(get_db)):
    sess = db.query(Session).filter(Session.id == session_id).first()
    if not sess:
        return RedirectResponse("/sessions", status_code=302)

    sess.review_status = "approved"
    sess.reviewed_at   = datetime.utcnow()

    # Build firewall rule
    rule_guid = str(uuid.uuid4()).upper()
    rule_name = f"NetMon-{sess.protocol.upper()}-{sess.dst_ip}-{sess.dst_port}"
    fw_rule = FirewallRule(
        guid=rule_guid,
        hostname=sess.hostname,
        name=rule_name,
        direction=direction,
        action=action,
        protocol=sess.protocol,
        src_ip=sess.src_ip if direction == "out" else sess.dst_ip,
        src_port=str(sess.src_port) if direction == "out" else str(sess.dst_port),
        dst_ip=sess.dst_ip if direction == "out" else sess.src_ip,
        dst_port=str(sess.dst_port) if direction == "out" else str(sess.src_port),
        status="deploying",
        session_id=sess.id,
    )
    db.add(fw_rule)
    db.flush()
    sess.rule_id = fw_rule.id
    db.commit()

    # Publish deploy order
    host = db.query(Host).filter(Host.hostname == sess.hostname).first()
    os_type = host.os_type if host else "linux"
    payload = {
        "guid":      rule_guid,
        "name":      rule_name,
        "os":        os_type,
        "direction": direction,
        "action":    action,
        "protocol":  sess.protocol,
        "src_ip":    fw_rule.src_ip,
        "src_port":  fw_rule.src_port,
        "dst_ip":    fw_rule.dst_ip,
        "dst_port":  fw_rule.dst_port,
    }
    mqtt_subscriber.publish_deploy(sess.hostname, payload)

    return RedirectResponse("/sessions?status=pending", status_code=302)


@router.post("/sessions/{session_id}/deny")
def deny_session(session_id: int, db: DBSession = Depends(get_db)):
    sess = db.query(Session).filter(Session.id == session_id).first()
    if sess:
        sess.review_status = "denied"
        sess.reviewed_at   = datetime.utcnow()
        db.commit()
    return RedirectResponse("/sessions?status=pending", status_code=302)
