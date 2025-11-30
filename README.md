# Merkle-Tree 기반 SBOM 추적 가능성 및 기밀성 검증 프레임워크  
**Repository:** 머클트리와 해시 체이닝 기반 SBOM 확장 모델_무결성, 추적성 및 선택적 기밀성 보장을 위한 접근

---

## 1. 개요 (Overview)

이 레포지토리는 **머클 트리(Merkle Tree) 해시 체이닝**을 활용하여  
소프트웨어 자재 명세서(**SBOM, Software Bill of Materials**)의

- **무결성(Integrity)**
- **추적 가능성(Traceability)**
- **기밀성(Confidentiality)**

을 동시에 검증할 수 있는 프로토타입 구현을 제공한다.

SBOM 항목을 블록 단위로 관리하고, 각 블록의 해시를 머클 트리 형태로 연결함으로써  
**임의 수정, 삭제, 재주입(rollback)** 등의 공격을 탐지하고,  
민감한 SBOM 항목은 암호화하여 **선별적 공개/검증**이 가능하도록 설계하였다.

---

## 2. 주요 아이디어 (Key Ideas)

1. **Merkle Tree + Hash Chaining**
   - SBOM 각 항목/버전을 노드로 관리
   - 각 노드는 `(메타데이터 + 페이로드)`에 대한 해시를 포함
   - 상위 노드는 자식 노드 해시를 기반으로 생성 → 변경 시 루트 해시가 변조 감지

2. **SBOM 추적 가능성 (Traceability)**
   - SBOM의 **버전/릴리즈 별 스냅샷**을 체인 형태로 연결
   - 특정 버전의 루트 해시(root hash)를 기준으로:
     - 해당 시점의 SBOM 전체 스냅샷 검증
     - 이후/이전 버전 간 변경 이력(diff) 추적

3. **SBOM 기밀성 (Confidentiality)**
   - SBOM 내 민감 필드(예: 내부 모듈명, 내부 레포지토리 URL 등)를 **선택적 암호화**
   - 검증자는 **해시에 기반한 무결성 검증**은 수행할 수 있지만,  
     권한이 없으면 내부 내용을 평문으로 열람할 수 없음

4. **경량 검증 (Lightweight Verification)**
   - 전체 SBOM을 전달하지 않고도
   - `루트 해시 + 인증 경로(Merkle proof)`만으로
   - 특정 항목이 원본 SBOM에 속하는지 검증 가능

---

## 3. 시스템 아키텍처 (Architecture)

```
├── sbom_merkle/                     
│   ├── __init__.py
│   ├── __init__.pyc
│   ├── bundle.py
│   ├── crypto.py
│   ├── main.py
│   ├── merkle.py
│   └── utils.py
├── LICENSE 
├── alpine.json   
├── pyproject.toml                  
├── README.md
└── requirements.txt
```

## 4. 빌드

```
python -m sbom_merkle.main build --in alpine.json --out alpine_bundle.json --stable-hash purl
```
