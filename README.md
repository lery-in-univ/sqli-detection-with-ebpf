# sqli-detection-with-ebpf

2026-1에 수강한 AI네트워킹 강의의 기말 프로젝트입니다.

> [!CAUTION]
> 본 프로젝트에 포함된 코드는 AI(Codex)와 함께 작성하였으며, PoC 수준의 코드입니다. 활용에 유의 바랍니다.

## 데이터

```bash
curl -L https://raw.githubusercontent.com/Morzeux/HttpParamsDataset/refs/heads/master/payload_full.csv -o data/payload_full.csv
```

- [HttpParamsDataset](https://github.com/Morzeux/HttpParamsDataset)을 활용하여 RandomForest 모델을 학습시킵니다.
- 위 스크립트를 실행하여 `data/` 디렉토리 하위에 파일을 다운로드합니다. 해당 파일은 git에 추적되지 않습니다.

## 실행

- 의존성 설치: `uv sync`
- Random Forest 학습: `uv run python -m src.training.train_rf`
- 감시 서버 실행: `uv run uvicorn src.monitor.app:app --host 127.0.0.1 --port 9000`
- 웹 서버 실행: `uv run uvicorn src.web_server.app:app --host 0.0.0.0 --port 8000`
- 성공 로그인: `admin` / `password`
- 로그인 API: `POST /login`
- 감시 이벤트 API: `POST /events/login`

## eBPF

- Lima VM 내부에서 실행
- BCC 기반 XDP 사용
- attach 인터페이스: `lo`
- XDP 모드: generic XDP
- 차단 기준: 최근 60초 내 RF와 LLM이 모두 SQLi로 판단한 이벤트 3회
