#!/usr/bin/env python3
"""Hybrid vulnerability assessment - Rule Engine phase.

Mapping key is ITEM/@code (U-001 ... U-100).

This phase performs rule-based assessment only.
AI/LLM/RAG inference is not executed here.

AI review trigger metadata is generated in result.xml
for later ai_assessment.py processing.
"""

from __future__ import annotations
import argparse, re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

RESULT_KOR={"GOOD":"양호","VULNERABLE":"취약","MANUAL":"수동점검","NA":"N/A"}

def get_text(parent,path,default=""):
    """
    XML 요소(parent)에서 지정한 경로(path)의 하위 노드를 찾고, 텍스트 값을 추출합니다.
    - parent가 None이거나 해당 경로의 노드가 없으면 default 값을 반환합니다.
    - 추출된 텍스트는 좌우 공백을 제거(strip)합니다.
    """
    if parent is None: return default
    n=parent.find(path)
    return (n.text or "").strip() if n is not None else default

def field_map(item):
    """
    XML 요소(item) 내 하위의 모든 <FIELDS/FIELD> 태그를 순회하며 
    'key' 속성을 기준으로 텍스트 값을 리스트로 그룹화하여 딕셔너리로 반환합니다.
    - 예: {'KEY1': ['val1', 'val2'], 'KEY2': ['val3']}
    """
    d=defaultdict(list)
    for f in item.findall("./FIELDS/FIELD"):
        d[f.get("key","")].append((f.text or "").strip())
    return dict(d)

def first(fields,key,default=""):
    """
    field_map()으로 만들어진 딕셔너리에서 특정 key의 첫 번째 값(리스트의 0번째 인덱스)을 반환합니다.
    - 해당 key가 없거나 리스트가 비어있으면 default 값을 반환합니다.
    """
    v=fields.get(key,[])
    return v[0] if v else default

def num(v):
    """
    입력값(v)을 실수(float)로 변환합니다.
    - 변환 실패(None, 문자열 에러 등) 시 예외를 발생시키지 않고 None을 반환합니다.
    """
    try:return float(v)
    except:return None

def splitv(v,i):
    """
    파이프 문자('|')로 구분된 문자열(v)을 분할하여 특정 인덱스(i)의 값을 추출합니다.
    - 인덱스 범위를 벗어나면 빈 문자열("")을 반환하며, 추출된 값은 좌우 공백을 제거합니다.
    """
    p=v.split("|")
    return p[i].strip() if 0 <= i < len(p) else ""

def octal(v):
    """
    8진수 형태의 문자열(v, 예: '755', '644')을 10진수 정수(int)로 변환합니다.
    - 변환 실패 시 예외를 발생시키지 않고 None을 반환합니다.
    """
    try:return int(v,8)
    except:return None

def add_derived(fields):
    f={k:list(v) for k,v in fields.items()}
    def b(key): return first(f,key,"false").lower()=="true"
    f["web_all_inactive"]=["true" if not b("apache_active") and not b("nginx_active") else "false"]
    f["db_all_inactive"]=["true" if not any(b(k) for k in ("mysql_active","postgres_active","mongo_active")) else "false"]
    f["was_all_inactive"]=["true" if not any(b(k) for k in ("tomcat_active","jboss_active","jeus_active")) else "false"]
    return f

def eval_rule(fields, rule):
    key=rule.get("key",""); op=rule.get("operator",""); exp=rule.get("expected","")
    vals=fields.get(key,[]); value=vals[0] if vals else ""; idx=int(rule.get("field_index","0"))
    if op=="equals": return value==exp, f"{key}={value or 'MISSING'}, expected={exp}"
    if op=="equals_ci": return value.lower()==exp.lower(), f"{key}={value or 'MISSING'}, expected={exp}"
    if op=="in":
        a={x.strip() for x in exp.split(",")}; return value in a, f"{key}={value}, allowed={sorted(a)}"
    if op=="in_ci":
        a={x.strip().lower() for x in exp.split(",")}; return value.lower() in a, f"{key}={value}, allowed={sorted(a)}"
    if op in ("greater_equal","less_equal"):
        a,b=num(value),num(exp)
        ok=a is not None and b is not None and (a>=b if op=="greater_equal" else a<=b)
        return ok, f"{key}={value}, {op} {exp}"
    if op=="between":
        p=[x.strip() for x in exp.split(",")]; a=num(value); lo=num(p[0]) if len(p)>1 else None; hi=num(p[1]) if len(p)>1 else None
        ok=a is not None and lo is not None and hi is not None and lo<=a<=hi
        return ok, f"{key}={value}, range={exp}"
    if op=="empty":
        ok=not [v for v in vals if v!=""]; return ok, f"{key} count={len(vals)}"
    if op=="all_split_in":
        a={x.strip() for x in exp.split(",")}; bad=[v for v in vals if splitv(v,idx) not in a]; return not bad, f"{key} bad={bad}"
    if op=="all_split_equals":
        bad=[v for v in vals if splitv(v,idx)!=exp]; return not bad, f"{key} bad={bad}"
    if op=="none_split_equals":
        bad=[v for v in vals if splitv(v,idx)==exp]; return not bad, f"{key} matched={bad}"
    if op=="none_split_regex":
        rx=re.compile(exp); bad=[v for v in vals if rx.search(splitv(v,idx))]; return not bad, f"{key} regex_matches={bad}"
    if op=="any_regex_ci":
        rx=re.compile(exp,re.I); ok=any(rx.search(v) for v in vals); return ok, f"{key} any_regex={exp}"
    if op=="all_split_numeric_between":
        p=[x.strip() for x in exp.split(",")]; lo=num(p[0]); hi=num(p[1]); bad=[]
        for v in vals:
            n=num(splitv(v,idx))
            if n is None or lo is None or hi is None or not lo<=n<=hi: bad.append(v)
        return not bad, f"{key} out_of_range={bad}"
    if op=="unique_split_field":
        c=Counter(splitv(v,idx) for v in vals); dup=[k for k,n in c.items() if k and n>1]; return not dup, f"{key} duplicates={dup}"
    if op=="uid_zero_only_root":
        bad=[splitv(v,1) for v in vals if splitv(v,0)=="0" and splitv(v,1)!="root"]; return not bad, f"UID0 non-root={bad}"
    if op=="all_mode_other_zero":
        bad=[]
        for v in vals:
            p=v.split("|"); mode=p[1].strip() if len(p)>1 else ""
            if not re.fullmatch(r"[0-7]{3,4}",mode) or mode[-1]!="0": bad.append(v)
        return not bad, f"other-permission bad={bad}"
    if op=="path_owner_mode_le":
        owner_req,mode_req=[x.strip() for x in exp.split(",",1)]
        bad=[]; existing=0
        for v in vals:
            p=v.split("|")
            if len(p)<6: bad.append(v); continue
            _,exists,mode,owner,_,_=p[:6]
            if exists!="true": continue
            existing+=1; mo=octal(mode); lim=octal(mode_req)
            if owner!=owner_req or mo is None or lim is None or mo>lim: bad.append(v)
        return existing>0 and not bad, f"{key}: existing={existing}, bad={bad}"
    return False, f"unsupported operator={op}"

def path_records(fields,key):
    out=[]
    for v in fields.get(key,[]):
        p=v.split("|")
        if len(p)>=6:
            out.append(dict(path=p[0],exists=p[1]=="true",mode=p[2],owner=p[3],group=p[4],type=p[5]))
    return out

def na_override(fields, criterion):
    for c in criterion.findall("./NA"):
        ok,detail=eval_rule(fields,c)
        if ok:
            return c.get("result","NA"), c.get("reason",detail)
    return None,""

def manual_override(fields, criterion):
    ma=criterion.find("./MANUAL_ALWAYS")
    if ma is not None:
        return True,ma.get("reason","수동점검 필요")
    for c in criterion.findall("./MANUAL"):
        ok,detail=eval_rule(fields,c)
        if ok:return True,c.get("reason",detail)
    return False,""

def special_override(fields, criterion):
    for c in criterion.findall("./SPECIAL"):
        ok,detail=eval_rule(fields,c)
        if ok:return c.get("result","MANUAL"),c.get("reason",detail)
    return None,""

def find_rule(c,role):
    for r in c.findall("./RULE"):
        if r.get("role")==role:return r
    return None

def boolf(fields,key): 
    return first(fields,key,"false").lower()=="true"

def all_generic_rules(fields,c):
    details=[]; rs=[]
    for r in c.findall("./RULE"):
        ok,d=eval_rule(fields,r); 
        rs.append(ok); 
        details.append(d)
    return bool(rs) and all(rs),details

def evaluate_item(raw_fields, c):
    fields=add_derived(raw_fields)
    na,reason=na_override(fields,c)
    if na:
        return na,reason,[reason]
    manual,reason=manual_override(fields,c)
    if manual:
        return "MANUAL",reason,[reason]
    special,reason=special_override(fields,c)
    if special:
        return special,reason,[reason]
    ev=get_text(c,"EVALUATOR","generic"); 
    details=[]; ok=None

    if ev=="su_restriction":
        a=find_rule(c,"pam_restriction"); 
        b=find_rule(c,"su_file_permissions")
        ao,d1=eval_rule(fields,a); 
        bo,d2=eval_rule(fields,b); 
        details=[d1,d2]; ok=ao or bo
    elif ev=="fail_lock_limit":
        ds=fields.get("pam_deny_value",[]); 
        mc=int(num(first(fields,"lock_module_count","0")) or 0)
        if ds:
            ok=all((num(v) is not None and 1<=num(v)<=10) for v in ds); 
            details=[f"PAM deny={ds}"]
        elif mc>0:
            v=first(fields,"faillock_deny_value","NOT_SET"); 
            n=num(v); ok=n is not None and 1<=n<=10; details=[f"faillock deny={v}"]
        else: ok=False; details=["잠금 PAM 모듈 미설정"]
    elif ev=="session_timeout":
        rr=[find_rule(c,x) for x in ("global","user_override")]; 
        vals=[eval_rule(fields,r) for r in rr]
        ok=all(x[0] for x in vals); details=[x[1] for x in vals]
        if boolf(fields,"csh_installed"):
            r=find_rule(c,"csh"); co,cd=eval_rule(fields,r); 
            cnt=int(num(first(fields,"csh_config_file_count","0")) or 0)
            ok=ok and co and cnt>0; details.append(f"csh files={cnt}; {cd}")
    elif ev=="password_policy":
        rules=c.findall("./RULE"); 
        normal=[r for r in rules if not (r.get("role") or "").startswith("complexity_option_")]
        vals=[eval_rule(fields,r) for r in normal]; 
        details=[d for _,d in vals]
        a=[r for r in rules if r.get("role")=="complexity_option_a"]; 
        b=[r for r in rules if r.get("role")=="complexity_option_b"]
        ao=all(eval_rule(fields,r)[0] for r in a) if a else False; 
        bo=all(eval_rule(fields,r)[0] for r in b) if b else False
        details.append(f"complexity A={ao}, B={bo}"); 
        ok=all(x[0] for x in vals) and (ao or bo)
    elif ev=="root_remote_login":
        a=find_rule(c,"service_disabled"); 
        b=find_rule(c,"ssh_setting"); 
        ao,d1=eval_rule(fields,a); 
        bo,d2=eval_rule(fields,b); 
        details=[d1,d2]; 
        ok=ao or bo
    elif ev=="cron_permissions":
        bad=[]; existing=0
        for key in ("cron_path","cron_member"):
            for r in path_records(fields,key):
                if not r["exists"]: continue
                existing+=1; mo=octal(r["mode"])
                lim=0o750 if r["path"] in ("/usr/bin/crontab","/usr/bin/at") or r["type"]=="directory" else 0o640
                if r["owner"]!="root" or mo is None or mo>lim: bad.append(r["path"]+"|"+r["mode"]+"|"+r["owner"])
        ok=existing>0 and not bad; details=[f"existing={existing}, bad={bad[:30]}"]
    elif ev=="ftpusers_permission":
        rec=[r for r in path_records(fields,"ftpusers_file") if r["exists"]]; bad=[]
        for r in rec:
            mo=octal(r["mode"])
            if r["owner"]!="root" or mo is None or mo>0o640: bad.append(r["path"])
        ok=bool(rec) and not bad; 
        details=[f"files={[r['path'] for r in rec]}, bad={bad}"]
    elif ev=="ftp_root_restriction":
        vals=fields.get("ftp_root_entry",[]); 
        ok=any(splitv(v,1)=="true" for v in vals); 
        details=[f"root control entries={vals}"]
    elif ev=="anonymous_share":
        if not any(boolf(fields,k) for k in ("ftp_active","nfs_active")) and not fields.get("samba_guest"):
            ok=True; details=["공유 서비스 활성 증적 없음"]
        else:
            # FTP is deterministic; NFS/Samba context can be ambiguous.
            ftp_ok=True
            if boolf(fields,"ftp_active"):
                txt=" ".join(fields.get("vsftpd_anonymous",[])).lower()
                ftp_ok=("anonymous_enable=no" in txt.replace(" ",""))
            nfs_amb=boolf(fields,"nfs_active")
            smb_txt=" ".join(fields.get("samba_guest",[])).lower()
            smb_bad=("guest ok = yes" in smb_txt or "guest ok=yes" in smb_txt)
            if nfs_amb:
                return "MANUAL","NFS 익명 접근 여부는 exports의 실제 네트워크/권한 범위를 수동 확인해야 함",[f"ftp_ok={ftp_ok}",f"samba_bad={smb_bad}"]
            ok=ftp_ok and not smb_bad; 
            details=[f"ftp_ok={ftp_ok}, samba_bad={smb_bad}"]
    elif ev=="remote_access_policy":
        tel=boolf(fields,"telnet_active"); 
        ssh=boolf(fields,"ssh_active")
        if tel: ok=False
        elif not ssh: ok=True
        else:
            ports=first(fields,"ssh_ports",""); 
            root=first(fields,"permitrootlogin","").lower()
            pset={x.strip() for x in ports.split(",") if x.strip()}
            ok=("22" not in pset) and root=="no"
        details=[f"telnet={tel}, ssh={ssh}, ports={first(fields,'ssh_ports')}, root={first(fields,'permitrootlogin')}"]
    elif ev=="nfs_access":
        lines=[v for v in fields.get("nfs_export",[]) if v not in ("NOT_SET","FILE_NOT_FOUND")]
        ok=bool(lines) and all("*" not in v for v in lines); details=[f"exports={lines[:20]}"]
    elif ev=="file_permission_nfs":
        rec=[r for r in path_records(fields,"exports_file") if r["exists"]]
        ok=bool(rec) and all(r["owner"]=="root" and octal(r["mode"]) is not None and octal(r["mode"])<=0o644 for r in rec)
        details=[str(rec)]
    elif ev=="smtp_restriction":
        txt=" ".join(fields.get("sendmail_privacy",[])+fields.get("postfix_restriction",[])).lower().replace(" ","")
        ok=any(x in txt for x in ("noexpn","novrfy","goaway","disable_vrfy_command=yes")); details=[txt[:1000]]
    elif ev=="dns_transfer":
        vals=fields.get("allow_transfer",[]); ok=bool(vals) and any(v not in ("NOT_SET","FILE_NOT_FOUND") for v in vals); details=[f"allow-transfer={vals}"]
    elif ev=="snmp_community":
        vals=[v for v in fields.get("snmp_community",[]) if v not in ("NOT_SET","FILE_NOT_FOUND")]
        bad=[v for v in vals if re.search(r"\b(public|private)\b",v,re.I)]
        ok=bool(vals) and not bad; details=[f"community lines={vals}, bad={bad}"]
    elif ev=="path_permission":
        ok,details=all_generic_rules(fields,c)
    elif ev.startswith("web_"):
        if fields["web_all_inactive"][0]=="true": return "NA","WEB 서비스 비활성화",["web inactive"]
        if ev=="web_dir_perm":
            rec=path_records(fields,"web_directory"); 
            bad=[r["path"] for r in rec if r["exists"] and (octal(r["mode"]) is None or octal(r["mode"])>0o755 or r["owner"] not in ("root","www-data","apache","nginx"))]
            ok=bool(rec) and not bad; 
            details=[f"bad={bad}"]
        elif ev=="web_file_perm":
            bad=[]; rec=[]
            for r in path_records(fields,"web_config"):
                if r["exists"]: rec.append(r); mo=octal(r["mode"]); 
                bad += [r["path"]] if mo is None or mo>0o640 else []
            for r in path_records(fields,"web_source"):
                if r["exists"]: rec.append(r); mo=octal(r["mode"]); 
                bad += [r["path"]] if mo is None or mo>0o644 else []
            ok=bool(rec) and not bad; details=[f"bad count={len(bad)}, sample={bad[:20]}"]
        elif ev=="web_upload_limit":
            vals=[v for v in fields.get("upload_limit",[]) if v not in ("NOT_SET","FILE_NOT_FOUND")]; 
            ok=bool(vals); details=[f"limits={vals}"]
        elif ev=="web_dir_traversal":
            vals=fields.get("dir_access_setting",[]); bad=[v for v in vals if re.search(r"AllowOverride\s+(?!None\b)",v,re.I)]; ok=not bad; details=[f"bad={bad[:20]}"]
        elif ev=="web_banner":
            vals=" ".join(fields.get("banner_setting",[]))
            apache=boolf(fields,"apache_active"); 
            nginx=boolf(fields,"nginx_active")
            aok=(not apache) or (re.search(r"ServerTokens\s+Prod\b",vals,re.I) and re.search(r"ServerSignature\s+Off\b",vals,re.I))
            nok=(not nginx) or re.search(r"server_tokens\s+off\b",vals,re.I)
            ok=bool(aok and nok); details=[f"settings={vals[:1000]}"]
        elif ev=="web_symlink":
            vals=fields.get("symlink_setting",[]); 
            ok=not vals; 
            details=[f"symlink settings={vals[:20]}"]
        elif ev=="web_cgi":
            vals=fields.get("cgi_setting",[]); 
            ok=not vals; 
            details=[f"cgi settings={vals[:20]}"]
        elif ev=="web_listing":
            vals=fields.get("listing_setting",[]); 
            ok=not vals; 
            details=[f"listing settings={vals[:20]}"]
        elif ev=="web_docroot":
            vals=fields.get("document_root_setting",[]); bad=[]
            for v in vals:
                m=re.search(r"(?:DocumentRoot|root)\s+[\"']?([^\"';\s]+)",v,re.I)
                if m and (m.group(1) in ("/var/www/html","/usr/share/nginx/html") or m.group(1).startswith(("/etc","/usr","/sys","/proc"))): bad.append(m.group(1))
            ok=bool(vals) and not bad; details=[f"roots={vals[:20]}, bad={bad}"]
        elif ev=="web_unnecessary":
            vals=fields.get("default_web_artifact",[]); 
            bad=[v for v in vals if splitv(v,1)=="true"]; 
            ok=not bad; details=[f"existing={bad}"]
        elif ev=="web_daemon_priv":
            vals=fields.get("web_process",[]); 
            users=[v.split(None,1)[0] for v in vals if v.strip()]
            ok=bool(users) and any(u!="root" for u in users); 
            details=[f"process users={users}"]
    elif ev=="umask":
        vals=[first(fields,"current_umask",""),first(fields,"login_defs_umask","")]
        parsed=[octal(v[-3:] if len(v)>3 else v) for v in vals if v and v!="NOT_SET"]
        ok=bool(parsed) and all(v is not None and v>=0o22 for v in parsed); 
        details=[f"umask={vals}"]
    elif ev=="inetd_permission":
        rec=[r for k in ("inetd_file","xinetd_dir") for r in path_records(fields,k) if r["exists"]]
        if not rec:return "NA","(x)inetd 관련 파일이 존재하지 않음",["no inetd/xinetd"]
        bad=[r["path"] for r in rec if r["owner"]!="root" or octal(r["mode"]) is None or octal(r["mode"])>0o600]
        ok=not bad;
        details=[f"bad={bad}"]
    elif ev=="syslog_permission":
        rec=[r for r in path_records(fields,"target_file") if r["exists"]]
        bad=[r["path"] for r in rec if r["owner"] not in ("root","bin","sys") or octal(r["mode"]) is None or octal(r["mode"])>0o644]
        ok=bool(rec) and not bad; 
        details=[f"bad={bad}"]
    elif ev=="home_env_permission":
        rec=[r for r in path_records(fields,"env_file") if r["exists"]]; bad=[]
        for r in rec:
            mo=octal(r["mode"]); user=Path(r["path"]).parts[2] if r["path"].startswith("/home/") and len(Path(r["path"]).parts)>2 else "root"
            if r["owner"] not in ("root",user) or mo is None or (mo & 0o022)!=0: bad.append(r["path"])
        ok=not bad; 
        details=[f"checked={len(rec)}, bad={bad[:20]}"]
    elif ev=="path_env":
        p=first(fields,"root_path",""); 
        parts=p.split(":"); 
        bad=("." in parts or "" in parts); 
        ok=bool(p) and not bad; 
        details=[f"PATH={p}"]
    elif ev=="ip_restrict":
        allow=[v for v in fields.get("hosts_allow",[]) if v not in ("NOT_SET","FILE_NOT_FOUND")]
        deny=[v for v in fields.get("hosts_deny",[]) if v not in ("NOT_SET","FILE_NOT_FOUND")]
        fw=first(fields,"firewall_tool","NOT_FOUND"); 
        ok=bool(deny) or fw!="NOT_FOUND"; 
        details=[f"deny_rules={len(deny)}, firewall={fw}"]
    elif ev=="services_permission":
        rec=path_records(fields,"target_file"); 
        ok=bool(rec) and all(r["owner"] in ("root","bin","sys") and octal(r["mode"]) is not None and octal(r["mode"])<=0o644 for r in rec if r["exists"]); 
        details=[str(rec)]
    elif ev=="service_patch":
        if not boolf(fields,"dns_active") and not boolf(fields,"smtp_active"): 
            ok=True; 
            details=["DNS/SMTP inactive"]
        else:return "MANUAL","활성 서비스 버전의 최신 보안패치 여부는 외부 기준과 대조 필요",[first(fields,"named_version"),first(fields,"sendmail_version"),first(fields,"postfix_version")]
    elif ev=="logging":
        conf=path_records(fields,"rsyslog_conf")+path_records(fields,"syslog_conf")
        ok=boolf(fields,"rsyslog_active") and any(r["exists"] for r in conf); 
        details=[f"daemon={first(fields,'rsyslog_active')}, conf={conf}"]
    elif ev=="log_permission":
        rec=[r for r in path_records(fields,"log_path") if r["exists"]]; 
        bad=[]
        for r in rec:
            mo=octal(r["mode"]); lim=0o755
            if r["path"].endswith("wtmp") or r["path"].endswith("lastlog"): lim=0o664
            elif r["path"].endswith("btmp"): lim=0o660
            elif r["path"].endswith(".conf"): lim=0o644
            if mo is None or mo>lim: bad.append(r["path"])
        ok=bool(rec) and not bad; 
        details=[f"bad={bad}"]
    elif ev.startswith("db_"):
        if fields["db_all_inactive"][0]=="true":return "NA","DBMS 서비스 비활성화",["DB inactive"]
        if ev=="db_remote":
            vals=fields.get("db_bind_setting",[])
            if not vals:return "MANUAL","DB bind/listen 설정을 자동 확인하지 못함",[]
            bad=[v for v in vals if re.search(r"(0\.0\.0\.0|\*|::)",v)]
            ok=not bad; 
            details=[f"bind={vals}, bad={bad}"]
        elif ev=="db_audit":
            vals=fields.get("db_audit_setting",[]); 
            ok=bool([v for v in vals if v not in ("NOT_SET","FILE_NOT_FOUND")]); 
            details=[f"audit={vals}"]
        elif ev=="db_umask":
            v=first(fields,"current_umask",""); o=octal(v[-3:] if len(v)>3 else v); 
            ok=o is not None and o>=0o22; 
            details=[f"umask={v}"]
        elif ev=="db_file_perm":
            rec=path_records(fields,"db_config_file")
            if not rec:return "MANUAL","DB 주요 설정 파일 경로를 자동 식별하지 못함",[]
            bad=[r["path"] for r in rec if octal(r["mode"]) is None or octal(r["mode"])>0o640]
            ok=not bad; 
            details=[f"bad={bad}"]
        elif ev=="db_resource":
            vals=fields.get("db_resource_setting",[]); 
            ok=bool([v for v in vals if v not in ("NOT_SET","FILE_NOT_FOUND")]); 
            details=[f"resource={vals}"]
        else:return "MANUAL","DB 인증/정책 또는 EOS 기준 대조가 필요한 항목",[]
    elif ev.startswith("was_"):
        if fields["was_all_inactive"][0]=="true":return "NA","WAS 서비스 비활성화",["WAS inactive"]
        if ev=="was_daemon_priv":
            vals=fields.get("was_process",[]); 
            users=[v.split(None,1)[0] for v in vals if v.strip()]; 
            ok=bool(users) and all(u!="root" for u in users); 
            details=[f"users={users}"]
        elif ev=="was_password_file":
            rec=path_records(fields,"was_password_file")
            if not rec:return "MANUAL","WAS 패스워드 파일 경로를 자동 식별하지 못함",[]
            bad=[r["path"] for r in rec if octal(r["mode"]) is None or octal(r["mode"])>0o640]; 
            ok=not bad; 
            details=[f"bad={bad}"]
        elif ev=="was_dir_perm":
            rec=path_records(fields,"was_directory")
            if not rec:return "MANUAL","WAS 홈 디렉터리 경로를 자동 식별하지 못함",[]
            bad=[r["path"] for r in rec if octal(r["mode"]) is None or octal(r["mode"])>0o755]; 
            ok=not bad; 
            details=[f"bad={bad}"]
        elif ev=="was_access_log":
            vals=fields.get("access_log_setting",[]); 
            ok=bool([v for v in vals if v not in ("NOT_SET","FILE_NOT_FOUND")]); 
            details=[f"log settings={vals}"]
        else:return "MANUAL","WAS 계정/패스워드/패치 기준은 제품별 설정 확인 필요",[]
    elif ev in ("osv","suspicious_count","generic"):
        ok,details=all_generic_rules(fields,c)
    elif ev=="manual":
        return "MANUAL","수동점검 항목",[]
    else:
        ok,details=all_generic_rules(fields,c)

    if ok:
        return "GOOD",get_text(c,"GOOD_REASON","기준 충족"),details
    return "VULNERABLE",get_text(c,"BAD_REASON","기준 미충족"),details

def display_lines(item):
    out=[]
    for f in item.findall("./FIELDS/FIELD"):
        key=f.get("key",""); 
        src=f.get("source",""); 
        note=f.get("note",""); 
        val=(f.text or "").strip()
        out.append(f"- {key}{' ['+src+']' if src else ''}{' ('+note+')' if note else ''}: {val}")
    return out

def build(evidence,criteria,xmlout,txtout):
    er=ET.parse(evidence).getroot(); 
    cr=ET.parse(criteria).getroot()

    cmap={i.get("code",""):
    i for i in cr.findall("./ITEM")}
    root=ET.Element("ASSESSMENT_RESULT",{"version":"2.0"})
    so=ET.SubElement(root,"SYSTEM"); 
    es=er.find("./SYSTEM")

    if es is not None:
        for ch in list(es): 
            ET.SubElement(so,ch.tag).text=ch.text or ""
    results=ET.SubElement(root,"RESULTS"); 
    summary=Counter(); sections=[]

    for ei in er.findall("./ITEM"):
        code=ei.get("code",""); 
        c=cmap.get(code); 
        name=get_text(ei,"NAME"); 
        fields=field_map(ei)

        if c is None: 
            result,reason,details="MANUAL","매핑되는 인증기준이 없음",[]; 
            grade=good=bad=""
        else:
            result,reason,details=evaluate_item(fields,c); 
            grade=get_text(c,"GRADE"); 
            good=get_text(c,"GOOD_STANDARD"); 
            bad=get_text(c,"BAD_STANDARD")
        summary[result]+=1
        
        io=ET.SubElement(results,"ITEM",{"code":code}); 
        ET.SubElement(io,"NAME").text=name; 
        ET.SubElement(io,"GRADE").text=grade
        
        st=ET.SubElement(io,"STANDARD"); 
        ET.SubElement(st,"GOOD").text=good; 
        ET.SubElement(st,"BAD").text=bad
        
        evn=ET.SubElement(io,"EVIDENCE")
        for f in ei.findall("./FIELDS/FIELD"):
            cp=ET.SubElement(evn,"FIELD",dict(f.attrib)); 
            cp.text=f.text or ""
        
        en=ET.SubElement(io,"EVALUATION"); 
        ET.SubElement(en,"RESULT").text=result; 
        ET.SubElement(en,"REASON").text=reason
        
        dn=ET.SubElement(en,"DETAILS")

        for d in details: 
            ET.SubElement(dn,"DETAIL").text=d
        
        # ----------------------------------------------------------
        # AI Review Trigger
        # ----------------------------------------------------------
        ai = ET.SubElement(io, "AI")

        if result == "MANUAL":
            ai_recommended = "true"
            trigger_reason = "RULE_MANUAL"
        
        elif result == "UNCERTAIN":
            ai_recommended = "true"
            trigger_reason = "RULE_UNCERTAIN"
        
        else:
            ai_recommended = "false"
            trigger_reason ="NONE"
        
        ET.SubElement(ai, "RECOMMENDED").text = ai_recommended
        ET.SubElement(ai, "TRIGGER_REASON").text = trigger_reason
        ET.SubElement(ai, "REVIEW").text = "false"


        # TXT 결과
        sep="="*78

        sections += [
            sep,f"{code}. {name}",
            sep,"▶ 시스템 현황",
            "",
            f"▶ {reason}",
            "",
            "-------------- < 시스템 설정 현황 > --------------",
            *display_lines(ei),
            "",
            f"★ {code}. 결과 : {RESULT_KOR.get(result,result)}",
            ""
            ]

    sn=ET.SubElement(root,"SUMMARY")

    for k in ("GOOD","VULNERABLE","MANUAL","NA"): 
        ET.SubElement(sn,k).text=str(summary.get(k,0))
    ET.indent(root,space="    "); 
    ET.ElementTree(root).write(xmlout,encoding="utf-8",xml_declaration=True)

    sv={x.tag:(x.text or "").strip() for x in list(es)} if es is not None else {}
    
    bar="="*141
    header=[bar,"Linux Vulnerability Assessment Result - Phase 1 (Rule Engine / No AI)",bar,
            f"Check Time : {sv.get('CHECK_TIME','')}",f"Hostname   : {sv.get('HOSTNAME','')}",f"Kernel     : {sv.get('KERNEL','')}",f"OS Version : {sv.get('OS_VERSION','')}",bar,""]
    footer=[bar,f"Summary - 양호: {summary.get('GOOD',0)}, 취약: {summary.get('VULNERABLE',0)}, 수동점검: {summary.get('MANUAL',0)}, N/A: {summary.get('NA',0)}",bar,""]
    txtout.write_text("\n".join(header+sections+footer),encoding="utf-8")

def main():
    p=argparse.ArgumentParser(description="U-001~U-100 no-AI rule engine")
    p.add_argument("evidence",type=Path)
    p.add_argument("-c","--criteria",type=Path,default=Path("criteria_u001_u100.xml"))
    p.add_argument("-o","--output",type=Path,default=Path("result.xml"))
    p.add_argument("--txt",type=Path,default=None)
    a=p.parse_args(); t=a.txt or a.output.with_suffix(".txt")
    build(a.evidence,a.criteria,a.output,t)
    print(f"[INFO] XML result: {a.output}"); print(f"[INFO] TXT result: {t}"); print("[INFO] AI/LLM/RAG was not used.")

if __name__=="__main__": main()
