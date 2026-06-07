from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import httpx
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()

MONITOR_EVENT_URL = "http://127.0.0.1:9000/events/login"
SUCCESS_CREDENTIALS = {
    ("admin", "password"),        # 일반적인 계정
    ("something", "' OR '1'='1"), # SQLi 비밀번호지만 등록된 계정
}


class LoginRequest(BaseModel):
    id: str
    password: str


@app.post("/login")
async def login(body: LoginRequest, request: Request, background_tasks: BackgroundTasks):
    status_code = 201 if (body.id, body.password) in SUCCESS_CREDENTIALS else 401
    event = {
        "request_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": request.client.host if request.client else "unknown",
        "method": "POST",
        "path": "/login",
        "status_code": status_code,
        "id": body.id,
        "password": body.password,
    }
    background_tasks.add_task(_send_event, event)
    return JSONResponse(
        status_code=status_code,
        content={"status": "success" if status_code == 201 else "failed"},
        background=background_tasks,
    )


async def _send_event(event: dict[str, object]) -> None:
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(MONITOR_EVENT_URL, json=event)
    except Exception as exc:
        print(f"[web] 이벤트 전송 실패: {exc}")
