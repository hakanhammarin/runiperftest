"""
Firewall rules management – view deployed rules, revoke them.
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DBSession
from datetime import datetime

from server.database import get_db, FirewallRule, Host
from server import mqtt_subscriber

router = APIRouter()
templates = Jinja2Templates(directory="server/templates")


@router.get("/rules", response_class=HTMLResponse)
def list_rules(request: Request, status: str = "all", db: DBSession = Depends(get_db)):
    q = db.query(FirewallRule)
    if status != "all":
        q = q.filter(FirewallRule.status == status)
    rules = q.order_by(FirewallRule.created_at.desc()).limit(500).all()
    return templates.TemplateResponse("rules.html", {
        "request": request,
        "rules": rules,
        "current_status": status,
    })


@router.post("/rules/{rule_id}/revoke")
def revoke_rule(rule_id: int, db: DBSession = Depends(get_db)):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if rule and rule.status not in ("revoked",):
        rule.status     = "revoked"
        rule.revoked_at = datetime.utcnow()
        db.commit()
        mqtt_subscriber.publish_revoke(rule.hostname, rule.guid)
    return RedirectResponse("/rules", status_code=302)


@router.post("/rules/{rule_id}/redeploy")
def redeploy_rule(rule_id: int, db: DBSession = Depends(get_db)):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        return RedirectResponse("/rules", status_code=302)
    rule.status     = "deploying"
    rule.deployed_at = None
    rule.error_msg   = None
    db.commit()

    host = db.query(Host).filter(Host.hostname == rule.hostname).first()
    os_type = host.os_type if host else "linux"
    payload = {
        "guid":      rule.guid,
        "name":      rule.name,
        "os":        os_type,
        "direction": rule.direction,
        "action":    rule.action,
        "protocol":  rule.protocol,
        "src_ip":    rule.src_ip,
        "src_port":  rule.src_port,
        "dst_ip":    rule.dst_ip,
        "dst_port":  rule.dst_port,
    }
    mqtt_subscriber.publish_deploy(rule.hostname, payload)
    return RedirectResponse("/rules", status_code=302)
