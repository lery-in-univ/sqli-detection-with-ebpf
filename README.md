# sqli-detection-with-ebpf

2026-1에 수강한 AI네트워킹 강의의 기말 프로젝트입니다.

> [!CAUTION]
> 본 프로젝트에 포함된 코드는 AI(Codex)와 함께 작성하였으며, 충분한 검토가 동반되지 않은 PoC 수준의 코드입니다. 활용에 유의 바랍니다.

## Prerequisites

- Python 3.10+
- limactl 2.1.1

## 데이터

```bash
curl -L https://raw.githubusercontent.com/Morzeux/HttpParamsDataset/refs/heads/master/payload_full.csv -o data/payload_full.csv
```

- [HttpParamsDataset](https://github.com/Morzeux/HttpParamsDataset)을 활용하여 RandomForest 모델을 학습시킵니다.
- 위 스크립트를 실행하여 `data/` 디렉토리 하위에 파일을 다운로드합니다. 해당 파일은 git에 추적되지 않습니다.

## 실행

```shell
# Lima VM 시작 (`Proceed with the current configuration` 선택)
limactl start --name=sqli-ebpf ./lima-config.yaml
```

```shell
# Lima VM 쉘 연결
limactl shell sqli-ebpf

# pip 업데이트
python3 -m pip install --upgrade pip

# 기본 의존성 설치
python3 -m pip install -r requirements.txt

# LLM 의존성 설치
python3 -m pip install --index-url https://download.pytorch.org/whl/cpu torch
python3 -m pip install -r requirements-llm.txt

# RandomForest 학습 실행
# `artifacts` 디렉토리 하위에 `rf_model.pkl`, `feature-schema.json`, `metrics.json` 파일이 생성됩니다.
python3 -m src.training.train_rf

# 감시 서버 실행
sudo -E python3 -m uvicorn src.monitor.app:app --host 127.0.0.1 --port 9000
```

```shell
# Lima VM 쉘 연결
limactl shell sqli-ebpf

# 웹 서버 실행
python3 -m uvicorn src.web_server.app:app --host 0.0.0.0 --port 8000
```

## 테스트

```shell
# 일반적인 요청
curl -i -X POST http://127.0.0.1:8000/login \
  -H 'Content-Type: application/json' \
  -d '{"id":"admin","password":"password"}'

# SQLi 포함 요청 (해당 요청이 60초 내 3번 시 차단)
curl -i -X POST http://127.0.0.1:8000/login \
    -H 'Content-Type: application/json' \
    -d '{"id":"admin OR 1=1","password":"x"}'

# SQLi 의심되나 실제 비밀번호로 등록된 경우
curl -i -X POST http://127.0.0.1:8000/login \
    -H 'Content-Type: application/json' \
    -d "{\"id\":\"something\",\"password\":\"' OR '1'='1\"}"
```

## 정리

```shell
# VM 정지
limactl stop sqli-ebpf

# VM 삭제
limactl delete sqli-ebpf
```

## eBPF

- Lima VM 내부에서 실행
- BCC 기반 XDP 사용
- attach 인터페이스: `lo`
- XDP 모드: generic XDP
- 차단 기준: 최근 60초 내 RF와 LLM이 모두 SQLi로 판단한 이벤트 3회

## LICENSE

[MIT License](./LICENSE)
