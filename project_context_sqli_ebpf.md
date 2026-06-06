# AI 네트워킹 프로젝트 컨텍스트: eBPF 기반 차단을 활용한 SQL Injection 탐지

## 1. 과제 배경

이 프로젝트는 학부 수준의 컴퓨터공학 네트워킹/AI 네트워킹 과제를 위한 것이다.

과제에서는 학생들이 다음 주제 중 하나를 선택하고, 학습 모델, 공개 데이터셋, 패킷 캡처 또는 eBPF 기반 커널 수준 패킷 처리를 사용하는 소프트웨어를 구현하도록 요구한다.

1. 공격 유형 식별 및 패킷 폐기
2. 라우팅 경로 최적화
3. 네트워크 트래픽 예측
4. 연합학습 집계 과정의 집단 통신 병목 해결

선택한 방향은 다음과 같다.

> **공격 유형 탐지 및 패킷 폐기**

이 프로젝트는 특히 **SQL Injection 시도**를 탐지하고, **eBPF/XDP 또는 tc-BPF**를 사용해 의심스러운 트래픽을 차단하는 데 초점을 둔다.

핵심 목표는 상용 수준의 보안 시스템을 만드는 것이 아니다. 목표는 다음을 보여줄 수 있는 학부 수준의 동작 가능한 프로토타입을 만드는 것이다.

- 공개 데이터셋 사용
- AI/ML 기반 공격 탐지
- eBPF를 통한 커널 수준 패킷 드롭
- PPT 발표와 데모에 적합한 엔드투엔드 소프트웨어 파이프라인

## 2. 제안 프로젝트 제목

가능한 제목:

> **AI-based SQL Injection Attempt Detection and eBPF-based Packet Blocking**

한국어 제목:

> **AI 기반 SQL Injection 시도 탐지 및 eBPF 기반 패킷 차단 시스템**

## 3. 왜 SQL Injection인가?

SQL Injection은 단순한 규칙 기반 로직만으로 안정적으로 탐지하기 어렵기 때문에 이 과제에 적합한 대상이다.

규칙 기반 탐지는 보통 다음과 같은 고정 키워드나 기호를 확인한다.

```text
'
"
OR
AND
UNION
SELECT
--
/*
=
```

하지만 이 접근 방식에는 두 가지 큰 문제가 있다.

첫째, 정상적인 사용자 입력에도 SQL과 비슷한 문자열이 포함될 수 있다. 예를 들어 사용자가 `union`, `select` 같은 단어를 검색하거나 `O'Reilly` 같은 이름을 입력할 수 있다. 시스템이 이런 토큰이 포함된 모든 요청을 차단하면 오탐이 발생할 수 있다.

둘째, 공격자는 다음과 같은 방법으로 SQL Injection 페이로드를 쉽게 변형할 수 있다.

- 대소문자 변경
- URL 인코딩
- 주석 삽입
- 공백 변경
- DBMS별 문법 사용
- 시간 기반 페이로드
- 불리언 기반 페이로드
- 난독화된 표현식

따라서 하나의 고정 문자열 패턴만 탐지하는 대신, ML 모델은 여러 특징을 함께 사용할 수 있다.

- 페이로드 길이
- 특수문자 비율
- 따옴표 개수
- SQL 키워드 개수
- 주석 토큰 개수
- URL 인코딩 비율
- 요청 빈도
- 실패 응답 비율
- 동일 출발지 IP의 반복 요청

이 점은 규칙 기반 탐지만 사용하는 대신 AI를 사용할 명확한 이유가 된다.

## 4. 데이터셋 논의

### 4.1 CICIDS2017

CICIDS2017은 Canadian Institute for Cybersecurity에서 제공하는 잘 알려진 침입 탐지 데이터셋이다.

공식 페이지:

https://www.unb.ca/cic/datasets/ids-2017.html

다음과 같은 여러 공격 범주를 포함한다.

- BENIGN
- FTP-Patator
- SSH-Patator
- DoS slowloris
- DoS Slowhttptest
- DoS Hulk
- DoS GoldenEye
- Heartbleed
- Web Attack - Brute Force
- Web Attack - XSS
- Web Attack - Sql Injection
- Infiltration
- Bot
- PortScan
- DDoS

하지만 CICIDS2017은 SQL Injection 전용 모델 학습에는 이상적이지 않다. SQL Injection 클래스의 샘플 수가 매우 적기 때문이다.

`Web Attack - Sql Injection` 클래스는 대략 다음 정도의 샘플만 포함한다.

```text
21 samples
```

이는 독립적인 SQL Injection 분류기를 학습하기에는 너무 적다. 80:20 학습/테스트 분할을 적용하면 학습에는 약 16-17개의 SQLi 샘플, 테스트에는 4-5개의 샘플만 사용된다. 모델은 일반적인 SQLi 특성을 학습하기보다 몇 개의 샘플을 암기할 가능성이 높다.

따라서 CICIDS2017은 원래의 IDS 동기 사례로 언급할 수 있지만, SQLi 중심 학습에는 다른 데이터셋을 사용하는 것이 좋다.

### 4.2 권장 데이터셋: HttpParamsDataset

권장 데이터셋:

https://www.kaggle.com/datasets/evg3n1j/httpparamsdataset

원본 GitHub:

https://github.com/Morzeux/HttpParamsDataset

이 데이터셋은 정상 또는 이상으로 라벨링된 HTTP 파라미터 값을 포함하므로 SQL Injection 부분에 더 적합하다.

보고된 라벨 분포:

```text
normal payloads: about 19,304
anomalous payloads: about 11,763
SQL Injection payloads: about 10,852
XSS payloads: about 532
Command Injection payloads: about 89
Path Traversal payloads: about 290
```

이 프로젝트에서는 다음만 사용한다.

```text
norm vs sqli
```

이렇게 하면 학습 문제가 단순해지고 SQL Injection 탐지와 직접적으로 연결된다.

### 4.3 대안 데이터셋: CSIC 2010 HTTP Dataset

CSIC 2010 HTTP Dataset도 가능한 대안 데이터셋이다.

데이터셋 페이지:

https://impactcybertrust.org/dataset_view?idDataset=940

이 데이터셋은 다음을 포함한다.

- 약 36,000개의 정상 HTTP 요청
- 25,000개 이상의 비정상 HTTP 요청
- SQL Injection, XSS, CRLF injection, buffer overflow, file disclosure, parameter tampering 등의 공격

이 데이터셋은 전체 HTTP 요청 트래픽에 더 가깝지만 전처리가 더 복잡할 수 있다. 실용적인 학부 구현에는 HttpParamsDataset이 더 쉽다.

## 5. 시스템 방향

프로젝트는 탐지와 차단을 분리해야 한다.

ML 모델과 HTTP 수준 특징 추출은 사용자 공간에서 실행되어야 한다.

eBPF 프로그램은 빠른 커널 수준 차단을 담당해야 한다.

권장 아키텍처:

```text
Client
  |
  v
Flask/FastAPI Test Web Server
  |
  v
User-space HTTP Monitor
  - request payload/query/body 추출
  - source IP 기록
  - request frequency 기록
  - response status code 기록
  - feature 생성
  - ML inference 실행
  |
  v
Suspicious IP detected
  |
  v
Update eBPF map
  |
  v
XDP/eBPF Program
  - src IP가 blocklist map에 있으면 DROP
  - 그렇지 않으면 PASS
```

중요한 설계 포인트:

> eBPF는 빠른 패킷 드롭을 담당하고, 사용자 공간 Python은 HTTP 파싱과 ML 추론을 담당한다.

이는 현실적인 설계다. SQL Injection은 애플리케이션 계층 공격이기 때문이다. eBPF/XDP는 L2-L4 패킷 처리에 강하지만, SQLi 페이로드, HTTP 경로, 쿼리 문자열, 요청 본문, HTTP 상태 코드는 L7 정보다.

또한 HTTPS를 사용하는 경우 TLS 종료 없이는 페이로드와 상태 코드를 패킷 수준에서 직접 검사할 수 없다. 데모에서는 localhost 또는 로컬 VM/테스트 네트워크에서 plain HTTP를 사용한다.

## 6. ML 모델을 위한 특징

첫 번째 모델은 HttpParamsDataset의 페이로드 수준 특징만 사용할 수 있다.

권장 페이로드 특징:

```text
payload_length
special_char_count
special_char_ratio
digit_count
alpha_count
quote_count
double_quote_count
semicolon_count
dash_count
comment_token_count
sql_keyword_count
url_encoding_count
url_encoding_ratio
space_count
operator_count
parenthesis_count
```

SQL 키워드 예시:

```text
select
union
where
from
insert
update
delete
drop
or
and
sleep
benchmark
information_schema
```

라이브 데모에서는 런타임 특징을 추가한다.

```text
src_ip_request_count_10s
src_ip_failed_response_count_10s
src_ip_4xx_count_10s
src_ip_5xx_count_10s
same_endpoint_request_count_10s
unique_payload_count_10s
avg_request_interval
failed_response_ratio_10s
```

자동화된 SQL Injection 시도는 같은 출발지 IP에서 조금씩 다른 페이로드로 반복 요청을 보내는 경우가 많기 때문에 이러한 특징이 유용하다.

## 7. 모델 선택

권장하는 단순 모델:

- Logistic Regression
- Random Forest
- 사용 가능하다면 XGBoost 또는 LightGBM
- 신경망 데모가 필요하다면 작은 MLP

이 과제에서는 Random Forest가 첫 번째 선택으로 가장 적합할 가능성이 높다.

- 학습이 쉽다.
- 사람이 설계한 수치 특징과 잘 맞는다.
- 큰 딥러닝 환경 구성이 필요 없다.
- 발표에서 설명하기 쉽다.
- 데모에 충분히 빠르다.

가능한 모델 구성:

```text
Input: HTTP parameter payload에서 추출한 numeric features
Output: normal 또는 SQL Injection
```

평가 지표:

```text
accuracy
precision
recall
F1-score
confusion matrix
```

보안 데이터셋은 불균형한 경우가 많기 때문에 accuracy보다 precision과 recall을 더 강조해야 한다.

## 8. 런타임 데모 계획

데모는 다음 구성 요소로 만들 수 있다.

### 8.1 테스트 웹 서버

Flask 또는 FastAPI를 사용한다.

예시 엔드포인트:

```text
/login?username=...
/search?q=...
/product?id=...
```

서버는 다음을 로그로 남겨야 한다.

- source IP
- path
- query string
- 필요한 경우 request body
- response status code
- timestamp

### 8.2 공격 트래픽 생성기

다음을 전송하는 Python 스크립트를 작성한다.

- 정상 요청
- SQLi와 유사한 요청
- 같은 IP 또는 같은 클라이언트에서 반복되는 요청

로컬 데모에서는 localhost에서 요청을 보낼 수 있다. 출발지 IP 변형이 필요하다면 network namespace, container를 사용하거나, 통제된 환경에서 클라이언트 IP 기준 차단을 단순히 시연할 수 있다.

### 8.3 ML 모니터

모니터는 다음을 수행해야 한다.

1. 요청 로그를 수신하거나 읽는다.
2. 최근 요청을 10초 윈도우로 집계한다.
3. 페이로드 및 빈도/상태 코드 특징을 추출한다.
4. 모델 추론을 실행한다.
5. 출발지 IP가 의심스러운지 판단한다.
6. eBPF blocklist map을 업데이트한다.

### 8.4 eBPF 차단

eBPF/XDP 프로그램은 다음을 수행해야 한다.

1. Ethernet/IP 헤더를 파싱한다.
2. source IP를 추출한다.
3. source IP가 BPF map에 존재하는지 확인한다.
4. 차단된 경우 `XDP_DROP`을 반환한다.
5. 그렇지 않으면 `XDP_PASS`를 반환한다.

단순화한 로직:

```c
if (src_ip in blocked_ips) {
    return XDP_DROP;
}
return XDP_PASS;
```

이렇게 하면 커널 로직을 단순하고 안정적으로 유지할 수 있다.

## 9. 예상 프로젝트 범위

최소 구현 범위:

1. HttpParamsDataset을 사용해 SQLi 탐지 모델을 학습한다.
2. 단순 HTTP 서버를 만든다.
3. 정상 및 SQLi 유사 트래픽을 위한 요청 생성기를 만든다.
4. 특징을 추출하고 모델 추론을 실행하는 사용자 공간 모니터를 만든다.
5. blocklist map에 저장된 IP를 차단하는 eBPF/XDP 프로그램을 만든다.
6. 반복적인 의심 SQLi 시도 이후 IP가 차단되는 것을 시연한다.
7. 모델 평가와 패킷 차단 결과를 PPT에 제시한다.

선택 확장:

- 응답 상태 코드를 추가 특징으로 사용
- 규칙 기반 탐지와 ML 기반 탐지 비교
- 규칙 기반 탐지가 지나치게 엄격한 오탐 사례 제시
- 대시보드/로그 출력 추가
- SQLi vs XSS 같은 여러 웹 공격 분류

## 10. 규칙 기반 vs ML 발표 포인트

PPT에 사용할 수 있는 유용한 비교:

규칙 기반 방법:

```text
if payload contains "union" or "select" or "'":
    block
```

문제점:

- 정상 텍스트에도 이러한 토큰이 포함될 수 있다.
- 공격자는 페이로드를 인코딩하거나 난독화할 수 있다.
- 고정 규칙은 취약하다.
- 많은 약한 신호를 결합하기 어렵다.

ML 기반 방법:

```text
payload structure
+ SQL keyword frequency
+ special character ratio
+ URL encoding ratio
+ repeated request count
+ failed response ratio
=> suspicious probability
```

장점:

- 여러 약한 신호를 결합할 수 있다.
- 의심스러운 조합을 탐지할 수 있다.
- 데이터를 사용해 조정하기 쉽다.
- 과제에서 요구하는 AI 기반 접근 방식을 명확히 보여준다.

## 11. 제안 PPT 구조

권장 슬라이드 개요:

1. 문제 정의
   - SQL Injection 시도는 단순 규칙만으로 탐지하기 어렵다.

2. 과제 주제 매핑
   - 주제 1: 공격 유형 탐지 및 패킷 폐기.

3. 데이터셋
   - CICIDS2017에는 SQLi 샘플이 21개뿐이다.
   - 약 10,852개의 SQLi 페이로드가 있는 HttpParamsDataset을 사용한다.

4. 시스템 아키텍처
   - 사용자 공간 ML 탐지 + eBPF 커널 드롭.

5. 특징 엔지니어링
   - 페이로드 특징, 요청 빈도, 응답 상태 코드.

6. 모델 학습 및 평가
   - Random Forest 또는 유사 모델.
   - accuracy, precision, recall, F1-score, confusion matrix.

7. eBPF/XDP 차단 로직
   - source IP blocklist map.

8. 데모 시나리오
   - 정상 요청은 통과한다.
   - 반복 SQLi 요청이 탐지된다.
   - source IP가 blocklist에 추가된다.
   - 이후 패킷은 드롭된다.

9. 결과
   - 모델 성능
   - 차단 전/후 동작
   - 패킷 드롭 로그 또는 카운터

10. 한계 및 향후 과제
    - HTTPS 페이로드는 XDP 수준에서 직접 검사할 수 없다.
    - SQLi 탐지는 사용자 공간에서 수행된다.
    - 더 현실적인 배포에는 reverse proxy, WAF 통합 또는 TLS termination이 필요하다.

## 12. 언급해야 할 중요한 한계

이 프로젝트는 프로토타입이므로 다음 한계를 솔직하게 밝혀야 한다.

- SQL Injection은 L7 웹 공격인 반면, XDP/eBPF는 주로 L2-L4를 다룬다.
- HTTP 상태 코드와 페이로드 파싱은 사용자 공간에서 처리된다.
- HTTPS 트래픽은 TLS termination 없이는 검사할 수 없다.
- 모델은 실제 운영 트래픽이 아니라 공개/합성 페이로드 데이터로 학습된다.
- IP 기반 차단은 NAT 뒤의 정상 사용자를 함께 차단할 수 있다.
- 데모는 상용 보안보다 엔드투엔드 동작을 우선한다.

이러한 한계는 명확히 설명하기만 한다면 학부 프로젝트에서는 수용 가능하다.

## 13. 최종 권장 방향

최종 프로젝트 방향:

> HttpParamsDataset을 사용해 SQL Injection 탐지 모델을 학습하고, 페이로드 특징과 요청 빈도 및 응답 상태 코드 특징을 결합하는 사용자 공간 HTTP 모니터를 구축한 뒤, eBPF/XDP를 사용해 의심스럽다고 분류된 IP의 패킷을 드롭한다.

이 방향은 과제 요구사항을 충족한다.

- 공개 데이터셋 사용
- AI/ML 모델 사용
- 네트워크 공격 탐지
- eBPF 기반 커널 패킷 처리
- 패킷 폐기
- 실용적인 데모
- 명확한 PPT 스토리
