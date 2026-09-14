Phase 1 Pure Rule Engine - U-001 ~ U-100
==========================================

구성
----
1) collect_evidence_u001_u100.sh
   - 시스템 설정/상태만 수집
   - 양호/취약/수동 판정 없음
   - generate_report 없음
   - T/F/R/NA 없음
   - ITEM 매핑 키는 code 하나만 사용: U-001 ~ U-100
   - internal_id 사용 안 함

2) criteria_u001_u100.xml
   - 100개 항목 기준
   - code="U-001" ~ code="U-100"
   - internal_id 없음
   - 규칙/수동/N/A 조건을 분리

3) assessment_u001_u100.py
   - evidence.xml + criteria.xml을 code로 매핑
   - GOOD / VULNERABLE / MANUAL / NA 판정
   - result.xml + result.txt 생성
   - AI/LLM/RAG 사용 안 함

4) run_scan.sh
   - collector와 assessment를 순서대로 호출하는 wrapper

실행
----
chmod +x collect_evidence_u001_u100.sh run_scan.sh

# 직접 실행
sudo ./collect_evidence_u001_u100.sh evidence.xml
python3 assessment_u001_u100.py evidence.xml -c criteria_u001_u100.xml -o result.xml

# wrapper
sudo ./run_scan.sh

주의
----
- U-001~U-010은 기존 검토 버전을 code-only 구조로 변경하였다.
- U-011~U-100은 원본 LINUX_5.7.1.sh의 100개 항목 명칭/기준을 반영해 확장하였다.
- OS/WAS/DB 제품별로 자동 식별이 불완전하거나 외부 EOS/최신패치 기준이 필요한 항목은
  억지로 GOOD/VULNERABLE을 내리지 않고 MANUAL 또는 N/A가 되도록 설계하였다.
- U-067~U-096은 기본적으로 $PWD/script/scan_results.txt를 증적으로 사용한다.
  경로 변경 시 OSV_RESULT 환경변수를 사용한다.
  예: OSV_RESULT=/path/scan_results.txt sudo -E ./run_scan.sh
- U-097은 CHKROOTKIT_RESULT, U-099는 WEBSHELL_RESULT 환경변수로 결과 파일 경로를 지정할 수 있다.

검증
----
- bash -n: 통과
- Python py_compile: 통과
- criteria XML: 100 ITEM, internal_id 0개 확인
- 테스트 실행: evidence.xml 100 ITEM 생성
- 테스트 실행: result.xml 100 ITEM 매핑 확인

중요
----
이 버전은 Phase 1 학습/리팩터링용이다.
실제 운영 적용 전에는 각 OS/서비스 조합에서 U-011~U-100의 수집 경로 및 판정 기준을
원본 도구 결과와 대조 테스트하는 것을 권장한다.
