import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from transformers import AutoTokenizer, AutoModelForCausalLM


# ============================================================
# 설정
# ============================================================

MODEL_NAME = "Qwen/Qwen2.5-0.5B-Instruct"

# 실제 /knowledge를 사용할 경우
KNOWLEDGE_DIR = Path("./knowledge")

# 프로젝트 내부 knowledge 폴더를 사용할 경우에는 아래처럼 변경
# KNOWLEDGE_DIR = Path(__file__).resolve().parent / "knowledge"


# ============================================================
# Knowledge Base 로드
# ============================================================

def load_knowledge(knowledge_dir=KNOWLEDGE_DIR):
    """
    /knowledge 디렉터리 내부의 모든 *.json 파일을 읽어
    하나의 knowledge dictionary로 병합한다.
    """

    knowledge_dir = Path(knowledge_dir)

    if not knowledge_dir.exists():
        raise FileNotFoundError(
            f"Knowledge 디렉터리가 존재하지 않습니다: {knowledge_dir}"
        )

    if not knowledge_dir.is_dir():
        raise NotADirectoryError(
            f"Knowledge 경로가 디렉터리가 아닙니다: {knowledge_dir}"
        )

    json_files = sorted(knowledge_dir.glob("*.json"))

    if not json_files:
        raise FileNotFoundError(
            f"{knowledge_dir} 디렉터리에 JSON 파일이 없습니다."
        )

    knowledge = {}

    print(f"[+] Knowledge Directory : {knowledge_dir}")
    print(f"[+] Knowledge Files     : {len(json_files)}")

    total = len(json_files)

    for index, json_file in enumerate(json_files, start=1):

        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # ------------------------------------------------
            # 형식 1
            #
            # {
            #     "U-01": {...}
            # }
            # ------------------------------------------------

            if isinstance(data, dict):

                # 단일 항목 파일
                # {
                #   "code": "U-01",
                #   "title": ...
                # }
                if "code" in data:

                    code = str(data["code"]).strip()

                    if code in knowledge:
                        print(
                            f"\n[!] Duplicate Knowledge ID: "
                            f"{code} ({json_file.name})"
                        )

                    knowledge[code] = data

                # 여러 항목이 들어 있는 파일
                else:
                    for code, item_data in data.items():

                        code = str(code).strip()

                        if code in knowledge:
                            print(
                                f"\n[!] Duplicate Knowledge ID: "
                                f"{code} ({json_file.name})"
                            )

                        knowledge[code] = item_data

            else:
                print(
                    f"\n[!] Skip invalid knowledge file: "
                    f"{json_file.name}"
                )

        except json.JSONDecodeError as e:
            print(
                f"\n[!] JSON Parsing Error "
                f"({json_file.name}): {e}"
            )

        except Exception as e:
            print(
                f"\n[!] Knowledge Load Error "
                f"({json_file.name}): {e}"
            )

        # 진행률 표시
        percent = (index / total) * 100

        print(
            f"\r[+] Loading Knowledge "
            f"[{index}/{total}] "
            f"{percent:6.2f}% "
            f"- {json_file.name}",
            end="",
            flush=True
        )

    print()
    print(f"[+] Loaded Knowledge Items : {len(knowledge)}")

    return knowledge


# ============================================================
# Local LLM 로드
# ============================================================

def load_model():

    print("[+] Loading Local LLM...")
    print(f"[+] Model : {MODEL_NAME}")

    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_NAME
    )

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        device_map="cpu"
    )

    model.eval()

    print("[+] Local LLM Loaded")

    return tokenizer, model


# ============================================================
# Knowledge 검색
# ============================================================

def retrieve_knowledge(code, knowledge):

    return knowledge.get(code)


# ============================================================
# XML AI REVIEW 여부
# ============================================================

def is_ai_review_enabled(criteria):

    """
    criteria.xml의 다음 값을 확인

    <AI>
        <REVIEW>true</REVIEW>
    </AI>

    true인 경우 AI 분석 수행
    """

    value = criteria.findtext(
        "./AI/REVIEW",
        default="false"
    )

    return value.strip().lower() == "true"


# ============================================================
# AI 설정 가져오기
# ============================================================

def get_ai_config(criteria):

    ai = criteria.find("./AI")

    if ai is None:
        return {
            "recommended": False,
            "trigger_reason": "NONE",
            "review": False
        }

    recommended = (
        ai.findtext("RECOMMENDED", "false")
        .strip()
        .lower()
        == "true"
    )

    trigger_reason = (
        ai.findtext("TRIGGER_REASON", "NONE")
        .strip()
    )

    review = (
        ai.findtext("REVIEW", "false")
        .strip()
        .lower()
        == "true"
    )

    return {
        "recommended": recommended,
        "trigger_reason": trigger_reason,
        "review": review
    }


# ============================================================
# Prompt 생성
# ============================================================

def build_prompt(
    code,
    evidence,
    knowledge_item,
    trigger_reason="NONE"
):

    kb_text = json.dumps(
        knowledge_item,
        ensure_ascii=False,
        indent=2
    )

    if isinstance(evidence, list):
        evidence_text = "\n".join(
            str(x)
            for x in evidence
        )
    else:
        evidence_text = str(evidence)

    prompt = f"""
당신은 Linux 서버 보안 취약점 진단 전문가입니다.

제공된 보안 기준과 시스템 증적만 사용하여
해당 점검 항목을 분석하십시오.

[점검 항목]
Code: {code}
제목: {knowledge_item.get("title", "")}

[AI 분석 요청 사유]
{trigger_reason}

[보안 지식]
{kb_text}

[시스템 수집 증적]
{evidence_text}

[판단 규칙]

1. 반드시 제공된 보안 지식과 시스템 증적만 사용한다.

2. 증적이 명확하게 보안 기준을 만족하면
   GOOD으로 판단한다.

3. 증적이 명확하게 보안 기준을 위반하면
   VULNERABLE로 판단한다.

4. 증적이 부족하거나 판단이 불가능하면
   반드시 MANUAL로 판단한다.

5. 존재하지 않는 설정이나 시스템 정보를
   추측해서는 안 된다.

6. confidence는 판단 근거의 충분성을
   0.0 ~ 1.0 사이 값으로 표현한다.

7. 반드시 JSON 형식으로만 응답한다.

8. reason에는 반드시 실제 시스템 증적의 key와 value를 하나 이상 인용하여 설명한다.

9. "보안 기준이 확인되었습니다", "증적이 명확합니다"와 같은
   추상적인 표현만으로 reason을 작성해서는 안 된다.

10. VULNERABLE인 경우:
    - 어떤 Evidence가
    - 어떤 기준을 위반했으며
    - 왜 취약한지
    구체적으로 작성한다.

11. GOOD인 경우:
    - 어떤 Evidence가
    - 어떤 양호 기준을 충족하는지
    구체적으로 작성한다.

12. MANUAL인 경우:
    - 현재 Evidence로 확인 가능한 부분
    - 확인할 수 없는 부분
    - 추가로 필요한 Evidence
    를 구분하여 작성한다.


출력 형식:

{{
    "result": "GOOD | VULNERABLE | MANUAL",
    "confidence": 0.0,
    "reason": "실제 Evidence의 설정값과 보안 기준을 직접 비교하여 2~4문장으로 구체적으로 설명",
    "matched_evidence": [
        "판단에 사용한 실제 증적"
    ],
    "criteria_analysis": [
        "증적과 비교한 기준"
    ]
}}
"""

    return prompt


# ============================================================
# LLM 실행
# ============================================================

def run_llm(tokenizer, model, prompt):

    messages = [
        {
            "role": "system",
            "content":
                "당신은 Linux 서버 보안 취약점 진단 전문가입니다."
        },
        {
            "role": "user",
            "content": prompt
        }
    ]

    text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True
    )

    inputs = tokenizer(
        text,
        return_tensors="pt"
    )

    outputs = model.generate(
        **inputs,
        max_new_tokens=300,
        do_sample=False,
        pad_token_id=tokenizer.eos_token_id
    )

    generated = outputs[0][
        inputs.input_ids.shape[1]:
    ]

    result = tokenizer.decode(
        generated,
        skip_special_tokens=True
    )

    return result


# ============================================================
# JSON 추출
# ============================================================

def extract_json(text):

    try:
        return json.loads(text)

    except json.JSONDecodeError:
        pass

    match = re.search(
        r"\{.*?\}",
        text,
        re.DOTALL
    )

    if not match:
        return None

    try:
        return json.loads(match.group())

    except json.JSONDecodeError:
        return None


# ============================================================
# AI 결과 Validation
# ============================================================

def validate_result(result):

    valid_results = {
        "GOOD",
        "VULNERABLE",
        "MANUAL"
    }

    ai_result = str(
        result.get("result", "MANUAL")
    ).upper()

    if ai_result not in valid_results:
        ai_result = "MANUAL"

    result["result"] = ai_result

    try:
        confidence = float(
            result.get("confidence", 0.0)
        )

    except (TypeError, ValueError):
        confidence = 0.0

    result["confidence"] = max(
        0.0,
        min(1.0, confidence)
    )

    reason = result.get("reason")

    if not reason:
        reason = "AI 판단 근거가 생성되지 않았습니다."

    result["reason"] = reason

    return result


# ============================================================
# AI 평가
# ============================================================

def evaluate_with_ai(
    code,
    evidence,
    knowledge,
    tokenizer,
    model,
    trigger_reason="NONE"
):

    kb = retrieve_knowledge(
        code,
        knowledge
    )

    # Knowledge가 없는 경우
    if kb is None:

        return {
            "result": "MANUAL",
            "confidence": 0.0,
            "reason":
                f"{code}에 대한 지식베이스가 없습니다.",
            "reference": []
        }

    prompt = build_prompt(
        code=code,
        evidence=evidence,
        knowledge_item=kb,
        trigger_reason=trigger_reason
    )

    raw_response = run_llm(
        tokenizer,
        model,
        prompt
    )

    parsed = extract_json(
        raw_response
    )

    if parsed is None:

        return {
            "result": "MANUAL",
            "confidence": 0.0,
            "reason":
                "AI 응답을 JSON으로 해석하지 못했습니다.",
            "reference":
                kb.get("reference", [])
        }

    parsed = validate_result(
        parsed
    )

    # Reference는 LLM에게 생성시키지 않음
    # Knowledge DB에서 Python이 직접 입력
    parsed["reference"] = kb.get(
        "reference",
        []
    )

    return parsed


# ============================================================
# 진행률 출력
# ============================================================

def print_progress(
    current,
    total,
    code=""
):

    if total <= 0:
        percent = 100.0
    else:
        percent = (
            current / total
        ) * 100

    bar_length = 30

    filled = int(
        bar_length
        * percent
        / 100
    )

    bar = (
        "#" * filled
        + "-" * (bar_length - filled)
    )

    print(
        f"\r[AI] [{bar}] "
        f"{percent:6.2f}% "
        f"({current}/{total}) "
        f"{code}",
        end="",
        flush=True
    )

    if current == total:
        print()


# ============================================================
# REVIEW=true 항목 일괄 AI 평가
# ============================================================

def evaluate_ai_items(
    items,
    knowledge,
    tokenizer,
    model
):

    """
    items 예:

    [
        {
            "code": "U-01",
            "criteria": XML Element,
            "evidence": [...]
        }
    ]
    """

    targets = []

    # REVIEW=true 항목만 추출
    for item in items:

        criteria = item["criteria"]

        ai_config = get_ai_config(
            criteria
        )

        if ai_config["review"]:

            item_copy = dict(item)

            item_copy["ai_config"] = ai_config

            targets.append(
                item_copy
            )

    total = len(targets)

    print(
        f"[+] AI REVIEW 대상 : "
        f"{total}개"
    )

    if total == 0:
        return []

    results = []

    for index, item in enumerate(
        targets,
        start=1
    ):

        code = item["code"]

        print_progress(
            index - 1,
            total,
            code
        )

        ai_config = item[
            "ai_config"
        ]

        result = evaluate_with_ai(
            code=code,
            evidence=item["evidence"],
            knowledge=knowledge,
            tokenizer=tokenizer,
            model=model,
            trigger_reason=ai_config[
                "trigger_reason"
            ]
        )

        result["code"] = code

        result["source"] = "AI"

        result["recommended"] = (
            ai_config["recommended"]
        )

        result["trigger_reason"] = (
            ai_config["trigger_reason"]
        )

        results.append(
            result
        )

        print_progress(
            index,
            total,
            code
        )

    return results
    
# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(
            f"Usage: python3 {sys.argv[0]} result.xml"
        )
        sys.exit(1)

    result_file = sys.argv[1]

    print(f"[+] Result XML : {result_file}")


    # ----------------------------------------
    # result.xml 로드
    # ----------------------------------------
    try:
        tree = ET.parse(result_file)
        root = tree.getroot()

    except Exception as e:
        print(
            f"[!] Result XML Load Error: {e}"
        )
        sys.exit(1)


    # ----------------------------------------
    # Knowledge 로드
    # ----------------------------------------
    knowledge = load_knowledge()


    # ----------------------------------------
    # REVIEW=true 항목 추출
    # ----------------------------------------
    review_items = []

    for item in root.findall(".//ITEM"):

        review = (
            item.findtext(
                "./AI/REVIEW",
                "false"
            )
            .strip()
            .lower()
            == "true"
        )

        if not review:
            continue


        code = item.get("code", "").strip()


        recommended = (
            item.findtext(
                "./AI/RECOMMENDED",
                "false"
            )
            .strip()
            .lower()
            == "true"
        )


        trigger_reason = (
            item.findtext(
                "./AI/TRIGGER_REASON",
                "NONE"
            )
            .strip()
        )


        # ------------------------------------
        # 증적 추출
        # ------------------------------------
        evidence = []

        for field in item.findall("./EVIDENCE/FIELD"):

            key = field.get("key", "").strip()
            value = (field.text or "").strip()
            source = field.get("source", "").strip()
            note = field.get("note", "").strip()
            line = f"{key} = {value}"
            
            if source:
                line += f" [source: {source}]"
            
            if note:
                line += f" [note: {note}]"
            
            evidence.append(line)
            
            # ------------------------------------
            # AI 분석 대상에 추가
            # ------------------------------------
            review_items.append(
                {
                    "code": code,
                    "evidence": evidence,
                    "ai_config": {
                        "review": review,
                        "recommended": recommended,
                        "trigger_reason": trigger_reason
                    }
                }
            )


    print(
        f"[+] AI REVIEW 대상 : "
        f"{len(review_items)}개"
    )


    if not review_items:

        print(
            "[+] AI 분석 대상이 없습니다."
        )

        sys.exit(0)


    # ----------------------------------------
    # LLM 로드
    # ----------------------------------------
    tokenizer, model = load_model()


    # ----------------------------------------
    # AI 분석
    # ----------------------------------------
    total = len(review_items)
    results = []


    for index, item in enumerate(
        review_items,
        start=1
    ):

        code = item["code"]

        print_progress(
            index - 1,
            total,
            code
        )

        ai_result = evaluate_with_ai(
            code=code,
            evidence=item["evidence"],
            knowledge=knowledge,
            tokenizer=tokenizer,
            model=model,
            trigger_reason=item[
                "ai_config"
            ]["trigger_reason"]
        )


        ai_result["code"] = code
        ai_result["source"] = "AI"

        results.append(
            ai_result
        )


        print_progress(
            index,
            total,
            code
        )


    # ----------------------------------------
    # 결과 출력
    # ----------------------------------------
    print()
    print("=" * 60)
    print("AI Analysis Result")
    print("=" * 60)


    for result in results:

        print(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2
            )
        )