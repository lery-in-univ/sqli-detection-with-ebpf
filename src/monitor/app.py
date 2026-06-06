from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass
from time import monotonic

from fastapi import FastAPI
from pydantic import BaseModel

from src.monitor.detector import RandomForestDetector
from src.monitor.ebpf import EbpfBlocker
from src.monitor.llm import QwenZeroShotVerifier

app = FastAPI()

SCORE_WINDOW_SECONDS = 60.0
BLOCK_THRESHOLD = 3


class LoginEvent(BaseModel):
    request_id: str | None = None
    timestamp: str
    source_ip: str
    method: str
    path: str
    status_code: int
    id: str
    password: str


@dataclass(frozen=True)
class LlmJob:
    event: LoginEvent
    rf_probability: float


detector = RandomForestDetector(threshold=0.7)
verifier = QwenZeroShotVerifier(timeout_seconds=10.0)
blocker = EbpfBlocker(interface="lo")
llm_queue: asyncio.Queue[LlmJob] = asyncio.Queue()
scores: dict[str, deque[float]] = defaultdict(deque)
blocked_ips: set[str] = set()


@app.on_event("startup")
async def startup() -> None:
    blocker.start()
    asyncio.create_task(_llm_worker())
    print("[monitor] 감시 서버 시작")


@app.on_event("shutdown")
async def shutdown() -> None:
    blocker.stop()


@app.post("/events/login")
async def receive_login_event(event: LoginEvent):
    print(f"[monitor] 이벤트 수신 ip={event.source_ip} status={event.status_code} id={event.id!r}")

    if event.status_code == 201:
        print("[monitor] 로그인 성공 이벤트 무시")
        return {"accepted": True, "ignored": "success"}

    is_sqli, probability = detector.is_login_sqli(event.id, event.password)
    print(f"[monitor] RF 결과 sqli={is_sqli} prob={probability:.3f}")

    if not is_sqli:
        return {"accepted": True, "rf_sqli": False}

    await llm_queue.put(LlmJob(event=event, rf_probability=probability))
    return {"accepted": True, "rf_sqli": True, "queued": True}


async def _llm_worker() -> None:
    while True:
        job = await llm_queue.get()
        try:
            await _process_llm_job(job)
        finally:
            llm_queue.task_done()


async def _process_llm_job(job: LlmJob) -> None:
    event = job.event
    if event.source_ip in blocked_ips:
        print(f"[monitor] 이미 차단된 IP 무시: {event.source_ip}")
        return

    llm_sqli = await verifier.is_sqli(event.id, event.password)
    print(f"[monitor] LLM 결과 sqli={llm_sqli} ip={event.source_ip}")

    if not llm_sqli:
        return

    score = _add_score(event.source_ip)
    print(f"[monitor] 의심 점수 ip={event.source_ip} score={score}/{BLOCK_THRESHOLD}")

    if score >= BLOCK_THRESHOLD:
        blocked_ips.add(event.source_ip)
        blocker.block_ip(event.source_ip)


def _add_score(source_ip: str) -> int:
    now = monotonic()
    entries = scores[source_ip]
    entries.append(now)

    while entries and now - entries[0] > SCORE_WINDOW_SECONDS:
        entries.popleft()

    return len(entries)
