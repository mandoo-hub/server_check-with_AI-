#!/usr/bin/env bash
set -u

# ==============================================================================
# Phase 1 - Pure Evidence Collector (U-001 ~ U-100)
# - 보안 판정(양호/취약/수동) 없음
# - generate_report 없음
# - T/F/R/NA 결과코드 없음
# - 시스템에서 관찰한 설정값/상태만 evidence.xml에 기록
# ==============================================================================

VERSION="1.0"
OUT_FILE="${1:-evidence.xml}"

xml_escape() {
    printf '%s' "$1" | sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g' \
        -e "s/'/\&apos;/g"
}

bool_xml() {
    [ "$1" = "true" ] && printf 'true' || printf 'false'
}

write_field() {
    local key="$1"
    local value="${2:-}"
    local source="${3:-}"
    local note="${4:-}"

    {
        printf '      <FIELD key="%s"' "$(xml_escape "$key")"
        [ -n "$source" ] && printf ' source="%s"' "$(xml_escape "$source")"
        [ -n "$note" ] && printf ' note="%s"' "$(xml_escape "$note")"
        printf '>%s</FIELD>\n' "$(xml_escape "$value")"
    } >> "$OUT_FILE"
}

begin_item() {
    local code="$1"
    local name="$2"
    {
        printf '  <ITEM code="%s">
' "$(xml_escape "$code")"
        printf '    <NAME>%s</NAME>
' "$(xml_escape "$name")"
        printf '    <FIELDS>\n'
    } >> "$OUT_FILE"
}

end_item() {
    {
        printf '    </FIELDS>\n'
        printf '  </ITEM>\n'
    } >> "$OUT_FILE"
}

# ------------------------------------------------------------------------------
# OS / path discovery
# ------------------------------------------------------------------------------
OS_TYPE="UNKNOWN"
CONF_PAM_SU="/etc/pam.d/su"
CONF_PASSWD="/etc/passwd"
CONF_SHADOW="/etc/shadow"
CONF_FAILLOCK="/etc/security/faillock.conf"
CONF_LOGIN_DEFS="/etc/login.defs"
CONF_PWQUALITY="/etc/security/pwquality.conf"
CONF_PWHISTORY="/etc/security/pwhistory.conf"
CONF_PROFILE="/etc/profile"
CONF_CSH_LOGIN="/etc/csh.login"
CONF_CSH_CSHRC="/etc/csh.cshrc"
CMD_SU_PATHS=("/bin/su" "/usr/bin/su")
OS_PAM_AUTH_FILES=()

if grep -q -i "amzn" /etc/os-release 2>/dev/null || grep -q -i "amazon" /etc/system-release 2>/dev/null; then
    OS_TYPE="AMAZON"
    OS_PAM_AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
elif [ -f /etc/redhat-release ]; then
    OS_TYPE="REDHAT"
    OS_PAM_AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
elif [ -f /etc/debian_version ]; then
    OS_TYPE="DEBIAN"
    OS_PAM_AUTH_FILES=("/etc/pam.d/common-auth" "/etc/pam.d/common-password")
elif [ -f /etc/SuSE-release ] || grep -q -i "suse" /etc/os-release 2>/dev/null; then
    OS_TYPE="SUSE"
    OS_PAM_AUTH_FILES=("/etc/pam.d/common-auth" "/etc/pam.d/common-password")
elif [ -f /etc/alpine-release ]; then
    OS_TYPE="ALPINE"
    OS_PAM_AUTH_FILES=("/etc/pam.d/base-auth" "/etc/pam.d/base-password")
else
    OS_PAM_AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/common-auth" "/etc/pam.d/common-password")
fi

# ------------------------------------------------------------------------------
# Service discovery / target selection / DB authentication
# ------------------------------------------------------------------------------
# 탐지(detected)와 점검 선택(selected)을 분리한다.
# 비밀번호는 evidence.xml에 기록하지 않으며 현재 Shell 메모리에서만 사용한다.

SVC_WEB_APACHE_DETECTED=false
SVC_WEB_NGINX_DETECTED=false
SVC_WAS_TOMCAT_DETECTED=false
SVC_WAS_JBOSS_DETECTED=false
SVC_WAS_JEUS_DETECTED=false
SVC_DB_MYSQL_DETECTED=false
SVC_DB_POSTGRES_DETECTED=false
SVC_DB_MONGO_DETECTED=false
SVC_DOCKER_DETECTED=false

SVC_WEB_APACHE=false
SVC_WEB_NGINX=false
SVC_WAS_TOMCAT=false
SVC_WAS_JBOSS=false
SVC_WAS_JEUS=false
SVC_DB_MYSQL=false
SVC_DB_POSTGRES=false
SVC_DB_MONGO=false
SVC_DOCKER=false

DOCKER_CIDS=()
DOCKER_NAMES=()
DOCKER_SERVICES=()
DOCKER_SELECTED=()

DB_MYSQL_CONNECTED=false
DB_MYSQL_AUTH_MODE="NONE"
DB_MYSQL_USER=""
DB_MYSQL_PW=""
CMD_MYSQL=""

DB_PG_CONNECTED=false
DB_PG_AUTH_MODE="NONE"
DB_PG_USER=""
DB_PG_PW=""
DB_PG_DB="postgres"
DB_PG_HOST="127.0.0.1"
DB_PG_PORT="5432"
CMD_PGSQL=""

DB_MONGO_CONNECTED=false
DB_MONGO_AUTH_MODE="NONE"
DB_MONGO_USER=""
DB_MONGO_PW=""
DB_MONGO_AUTH_DB="admin"
DB_MONGO_PORT="27017"
CMD_MONGO=""

_host_process_exists() {
    local pattern="$1"
    local pid
    while IFS= read -r pid; do
        [ -n "$pid" ] || continue
        # Docker/Kubernetes/Podman 컨테이너 프로세스는 Host 서비스에서 제외
        if ! grep -qE 'docker|containerd|kubepods|libpod|podman' "/proc/${pid}/cgroup" 2>/dev/null; then
            return 0
        fi
    done < <(pgrep -f "$pattern" 2>/dev/null || true)
    return 1
}

_detect_container_services() {
    local cid="$1"
    local procs services=""
    procs="$(docker top "$cid" -eo args 2>/dev/null || docker top "$cid" 2>/dev/null || true)"
    printf '%s\n' "$procs" | grep -Eqi '(^|[/[:space:]])(httpd|apache2)([[:space:]]|$)' && services+=" Apache"
    printf '%s\n' "$procs" | grep -Eqi '(^|[/[:space:]])nginx([[:space:]]|$)' && services+=" Nginx"
    printf '%s\n' "$procs" | grep -Eqi 'tomcat|catalina' && services+=" Tomcat"
    printf '%s\n' "$procs" | grep -Eqi 'jboss|wildfly|standalone\.sh' && services+=" JBoss"
    printf '%s\n' "$procs" | grep -Eqi 'jeus' && services+=" JEUS"
    printf '%s\n' "$procs" | grep -Eqi 'mysqld|mariadbd' && services+=" MySQL"
    printf '%s\n' "$procs" | grep -Eqi 'postgres|postmaster' && services+=" PostgreSQL"
    printf '%s\n' "$procs" | grep -Eqi 'mongod' && services+=" MongoDB"
    [ -n "$services" ] && printf '%s' "${services# }" || printf 'Unknown'
}

detect_target_services() {
    echo "[INFO] 실행 중인 WEB/WAS/DB/Docker 서비스를 탐지합니다..."

    _host_process_exists '(^|/)(httpd|apache2)([[:space:]]|$)' && SVC_WEB_APACHE_DETECTED=true
    _host_process_exists '(^|/)nginx([[:space:]]|$)' && SVC_WEB_NGINX_DETECTED=true
    _host_process_exists 'tomcat|catalina' && SVC_WAS_TOMCAT_DETECTED=true
    _host_process_exists 'jboss|wildfly|standalone\.sh' && SVC_WAS_JBOSS_DETECTED=true
    _host_process_exists 'jeus' && SVC_WAS_JEUS_DETECTED=true
    _host_process_exists 'mysqld|mariadbd' && SVC_DB_MYSQL_DETECTED=true
    _host_process_exists 'postgres|postmaster' && SVC_DB_POSTGRES_DETECTED=true
    _host_process_exists 'mongod' && SVC_DB_MONGO_DETECTED=true

    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        SVC_DOCKER_DETECTED=true
        local cid name services
        while IFS= read -r cid; do
            [ -n "$cid" ] || continue
            name="$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's#^/##')"
            services="$(_detect_container_services "$cid")"
            DOCKER_CIDS+=("$cid")
            DOCKER_NAMES+=("${name:-unknown}")
            DOCKER_SERVICES+=("$services")
            DOCKER_SELECTED+=("true")
        done < <(docker ps -q 2>/dev/null || true)
    fi

    # 기본 선택값 = 자동 탐지 결과
    SVC_WEB_APACHE="$SVC_WEB_APACHE_DETECTED"
    SVC_WEB_NGINX="$SVC_WEB_NGINX_DETECTED"
    SVC_WAS_TOMCAT="$SVC_WAS_TOMCAT_DETECTED"
    SVC_WAS_JBOSS="$SVC_WAS_JBOSS_DETECTED"
    SVC_WAS_JEUS="$SVC_WAS_JEUS_DETECTED"
    SVC_DB_MYSQL="$SVC_DB_MYSQL_DETECTED"
    SVC_DB_POSTGRES="$SVC_DB_POSTGRES_DETECTED"
    SVC_DB_MONGO="$SVC_DB_MONGO_DETECTED"
    SVC_DOCKER="$SVC_DOCKER_DETECTED"
}

_status_label() {
    [ "$1" = true ] && printf 'DETECTED' || printf '-'
}

show_target_services() {
    echo
    echo "=============================================================================="
    echo " 점검 대상 서비스 자동 탐지 결과"
    echo "=============================================================================="
    printf ' [1] WEB  - Apache      : %s\n' "$(_status_label "$SVC_WEB_APACHE_DETECTED")"
    printf ' [2] WEB  - Nginx       : %s\n' "$(_status_label "$SVC_WEB_NGINX_DETECTED")"
    printf ' [3] WAS  - Tomcat      : %s\n' "$(_status_label "$SVC_WAS_TOMCAT_DETECTED")"
    printf ' [4] WAS  - JBoss       : %s\n' "$(_status_label "$SVC_WAS_JBOSS_DETECTED")"
    printf ' [5] WAS  - JEUS        : %s\n' "$(_status_label "$SVC_WAS_JEUS_DETECTED")"
    printf ' [6] DB   - MySQL       : %s\n' "$(_status_label "$SVC_DB_MYSQL_DETECTED")"
    printf ' [7] DB   - PostgreSQL  : %s\n' "$(_status_label "$SVC_DB_POSTGRES_DETECTED")"
    printf ' [8] DB   - MongoDB     : %s\n' "$(_status_label "$SVC_DB_MONGO_DETECTED")"
    printf ' [9] SYS  - Docker      : %s\n' "$(_status_label "$SVC_DOCKER_DETECTED")"

    if [ "$SVC_DOCKER_DETECTED" = true ]; then
        echo "------------------------------------------------------------------------------"
        echo " Docker Container"
        if [ "${#DOCKER_CIDS[@]}" -eq 0 ]; then
            echo "  - 실행 중인 컨테이너 없음"
        else
            local i
            for i in "${!DOCKER_CIDS[@]}"; do
                printf ' [%d] %-12s  %-22s  %s\n' "$((i+1))" "${DOCKER_CIDS[$i]:0:12}" "${DOCKER_NAMES[$i]}" "${DOCKER_SERVICES[$i]}"
            done
        fi
    fi
    echo "=============================================================================="
}

select_target_services() {
    local answer exclude num
    echo
    read -r -p "탐지된 서비스를 모두 점검하시겠습니까? [Y/n]: " answer < /dev/tty || answer=""

    case "$answer" in
        n|N)
            echo "제외할 HOST 서비스 번호를 입력하세요. (예: 2 4 8 / 없으면 Enter)"
            read -r -p "> " exclude < /dev/tty || exclude=""
            for num in $exclude; do
                case "$num" in
                    1) SVC_WEB_APACHE=false ;;
                    2) SVC_WEB_NGINX=false ;;
                    3) SVC_WAS_TOMCAT=false ;;
                    4) SVC_WAS_JBOSS=false ;;
                    5) SVC_WAS_JEUS=false ;;
                    6) SVC_DB_MYSQL=false ;;
                    7) SVC_DB_POSTGRES=false ;;
                    8) SVC_DB_MONGO=false ;;
                    9) SVC_DOCKER=false ;;
                esac
            done
            ;;
        *) : ;;
    esac

    # Docker Daemon을 점검 대상으로 유지한 경우 컨테이너별 제외 기능 제공
    if [ "$SVC_DOCKER" = true ] && [ "${#DOCKER_CIDS[@]}" -gt 0 ]; then
        echo
        echo "[Docker] 점검에서 제외할 컨테이너 번호를 입력하세요. (예: 1 3 / 없으면 Enter)"
        local i
        for i in "${!DOCKER_CIDS[@]}"; do
            printf ' [%d] %-12s  %-22s  %s\n' "$((i+1))" "${DOCKER_CIDS[$i]:0:12}" "${DOCKER_NAMES[$i]}" "${DOCKER_SERVICES[$i]}"
        done
        read -r -p "> " exclude < /dev/tty || exclude=""
        for num in $exclude; do
            if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "${#DOCKER_CIDS[@]}" ]; then
                DOCKER_SELECTED[$((num-1))]="false"
            fi
        done
    fi

    echo
    echo "[INFO] 최종 점검 대상"
    printf '  WEB : Apache=%s, Nginx=%s\n' "$SVC_WEB_APACHE" "$SVC_WEB_NGINX"
    printf '  WAS : Tomcat=%s, JBoss=%s, JEUS=%s\n' "$SVC_WAS_TOMCAT" "$SVC_WAS_JBOSS" "$SVC_WAS_JEUS"
    printf '  DB  : MySQL=%s, PostgreSQL=%s, MongoDB=%s\n' "$SVC_DB_MYSQL" "$SVC_DB_POSTGRES" "$SVC_DB_MONGO"
    printf '  SYS : Docker=%s\n' "$SVC_DOCKER"
    if [ "$SVC_DOCKER" = true ] && [ "${#DOCKER_CIDS[@]}" -gt 0 ]; then
        local selected_count=0
        for i in "${!DOCKER_CIDS[@]}"; do
            if [ "${DOCKER_SELECTED[$i]}" = true ]; then
                selected_count=$((selected_count+1))
                printf '    [+] %s (%s) - %s\n' "${DOCKER_NAMES[$i]}" "${DOCKER_CIDS[$i]:0:12}" "${DOCKER_SERVICES[$i]}"
            else
                printf '    [-] %s (%s) - 제외\n' "${DOCKER_NAMES[$i]}" "${DOCKER_CIDS[$i]:0:12}"
            fi
        done
        printf '    선택된 컨테이너: %d/%d\n' "$selected_count" "${#DOCKER_CIDS[@]}"
    fi
}

mysql_query() {
    local query="$1"
    [ "$DB_MYSQL_CONNECTED" = true ] || return 1
    if [ "$DB_MYSQL_AUTH_MODE" = "SOCKET" ]; then
        "$CMD_MYSQL" -u "$DB_MYSQL_USER" -NBe "$query" 2>/dev/null
    else
        MYSQL_PWD="$DB_MYSQL_PW" "$CMD_MYSQL" -u "$DB_MYSQL_USER" -NBe "$query" 2>/dev/null
    fi
}

pg_query() {
    local query="$1"
    [ "$DB_PG_CONNECTED" = true ] || return 1
    if [ "$DB_PG_AUTH_MODE" = "PEER" ]; then
        su - postgres -c "${CMD_PGSQL} -d ${DB_PG_DB} -Atqc \"${query//\"/\\\"}\"" 2>/dev/null
    else
        PGPASSWORD="$DB_PG_PW" "$CMD_PGSQL" -h "$DB_PG_HOST" -p "$DB_PG_PORT" -U "$DB_PG_USER" -d "$DB_PG_DB" -Atqc "$query" 2>/dev/null
    fi
}

mongo_query() {
    local js="$1"
    [ "$DB_MONGO_CONNECTED" = true ] || return 1
    if [ "$DB_MONGO_AUTH_MODE" = "LOCAL" ]; then
        "$CMD_MONGO" --quiet --port "$DB_MONGO_PORT" --eval "$js" 2>/dev/null
    else
        "$CMD_MONGO" --quiet --host 127.0.0.1 --port "$DB_MONGO_PORT" \
            -u "$DB_MONGO_USER" -p "$DB_MONGO_PW" --authenticationDatabase "$DB_MONGO_AUTH_DB" \
            --eval "$js" 2>/dev/null
    fi
}

setup_db_auth() {
    local user pw db host port

    # MySQL / MariaDB: Unix socket 무암호/소켓 인증 -> 계정/암호 입력 순서
    if [ "$SVC_DB_MYSQL" = true ]; then
        CMD_MYSQL="$(command -v mysql 2>/dev/null || command -v mariadb 2>/dev/null || true)"
        echo
        echo "[DB] MySQL/MariaDB 인증 확인"
        if [ -z "$CMD_MYSQL" ]; then
            echo "  [WARN] mysql/mariadb 클라이언트를 찾지 못해 DB 내부 진단을 건너뜁니다."
        elif "$CMD_MYSQL" -u root -NBe 'SELECT 1' >/dev/null 2>&1 && \
             "$CMD_MYSQL" -u root -NBe 'SELECT User FROM mysql.user LIMIT 1' >/dev/null 2>&1; then
            DB_MYSQL_CONNECTED=true
            DB_MYSQL_AUTH_MODE="SOCKET"
            DB_MYSQL_USER="root"
            echo "  [OK] Unix Socket 인증으로 DBA 접근 성공."
        else
            echo "  [INFO] Socket 인증 실패 -> 계정 인증을 시도합니다."
            while true; do
                read -r -p "  MySQL DBA ID (기본 root / 건너뛰기 q): " user < /dev/tty || user="q"
                [ "$user" = "q" ] || [ "$user" = "Q" ] && break
                user="${user:-root}"
                read -r -s -p "  MySQL DBA Password: " pw < /dev/tty || pw=""
                echo
                if MYSQL_PWD="$pw" "$CMD_MYSQL" -u "$user" -NBe 'SELECT User FROM mysql.user LIMIT 1' >/dev/null 2>&1; then
                    DB_MYSQL_CONNECTED=true
                    DB_MYSQL_AUTH_MODE="PASSWORD"
                    DB_MYSQL_USER="$user"
                    DB_MYSQL_PW="$pw"
                    echo "  [OK] MySQL 계정 인증 및 시스템 테이블 조회 성공."
                    break
                fi
                echo "  [ERROR] 로그인 실패 또는 DBA 권한 부족. 다시 입력하거나 q로 건너뛰세요."
            done
        fi
    fi

    # PostgreSQL: 로컬 Unix socket + peer(su - postgres) -> 계정/암호(TCP localhost) 순서
    if [ "$SVC_DB_POSTGRES" = true ]; then
        CMD_PGSQL="$(command -v psql 2>/dev/null || true)"
        echo
        echo "[DB] PostgreSQL 인증 확인"
        if [ -z "$CMD_PGSQL" ]; then
            echo "  [WARN] psql 클라이언트를 찾지 못해 DB 내부 진단을 건너뜁니다."
        elif command -v su >/dev/null 2>&1 && su - postgres -c "$CMD_PGSQL -d postgres -Atqc 'SELECT 1'" >/dev/null 2>&1; then
            DB_PG_CONNECTED=true
            DB_PG_AUTH_MODE="PEER"
            DB_PG_USER="postgres"
            DB_PG_DB="postgres"
            echo "  [OK] Unix Socket/peer 인증(su - postgres) 성공."
        else
            echo "  [INFO] peer 인증 실패 -> 계정 인증을 시도합니다."
            while true; do
                read -r -p "  PostgreSQL DBA ID (기본 postgres / 건너뛰기 q): " user < /dev/tty || user="q"
                [ "$user" = "q" ] || [ "$user" = "Q" ] && break
                user="${user:-postgres}"
                read -r -p "  Database (기본 postgres): " db < /dev/tty || db="postgres"
                db="${db:-postgres}"
                read -r -p "  Host (기본 127.0.0.1): " host < /dev/tty || host="127.0.0.1"
                host="${host:-127.0.0.1}"
                read -r -p "  Port (기본 5432): " port < /dev/tty || port="5432"
                port="${port:-5432}"
                read -r -s -p "  PostgreSQL DBA Password: " pw < /dev/tty || pw=""
                echo
                if PGPASSWORD="$pw" "$CMD_PGSQL" -h "$host" -p "$port" -U "$user" -d "$db" -Atqc \
                    "SELECT CASE WHEN rolsuper THEN 1 ELSE 0 END FROM pg_roles WHERE rolname=current_user" 2>/dev/null | grep -q '^1$'; then
                    DB_PG_CONNECTED=true
                    DB_PG_AUTH_MODE="PASSWORD"
                    DB_PG_USER="$user"
                    DB_PG_PW="$pw"
                    DB_PG_DB="$db"
                    DB_PG_HOST="$host"
                    DB_PG_PORT="$port"
                    echo "  [OK] PostgreSQL 계정 인증 및 DBA 권한 확인 성공."
                    break
                fi
                echo "  [ERROR] 로그인 실패 또는 DBA 권한 부족. 다시 입력하거나 q로 건너뛰세요."
            done
        fi
    fi

    # MongoDB: localhost 무인증 접근 -> 계정/암호 순서
    if [ "$SVC_DB_MONGO" = true ]; then
        CMD_MONGO="$(command -v mongosh 2>/dev/null || command -v mongo 2>/dev/null || true)"
        echo
        echo "[DB] MongoDB 인증 확인"
        if [ -z "$CMD_MONGO" ]; then
            echo "  [WARN] mongosh/mongo 클라이언트를 찾지 못해 DB 내부 진단을 건너뜁니다."
        elif "$CMD_MONGO" --quiet --port "$DB_MONGO_PORT" --eval 'db.runCommand({ping:1}).ok' 2>/dev/null | grep -q '1'; then
            DB_MONGO_CONNECTED=true
            DB_MONGO_AUTH_MODE="LOCAL"
            echo "  [OK] localhost 로컬 접근 성공."
        else
            echo "  [INFO] 로컬 무인증 접근 실패 -> 계정 인증을 시도합니다."
            while true; do
                read -r -p "  MongoDB DBA ID (기본 admin / 건너뛰기 q): " user < /dev/tty || user="q"
                [ "$user" = "q" ] || [ "$user" = "Q" ] && break
                user="${user:-admin}"
                read -r -p "  Authentication DB (기본 admin): " db < /dev/tty || db="admin"
                db="${db:-admin}"
                read -r -s -p "  MongoDB DBA Password: " pw < /dev/tty || pw=""
                echo
                if "$CMD_MONGO" --quiet --host 127.0.0.1 --port "$DB_MONGO_PORT" \
                    -u "$user" -p "$pw" --authenticationDatabase "$db" \
                    --eval 'db.runCommand({connectionStatus:1}).authInfo.authenticatedUsers.length' 2>/dev/null | grep -Eq '[1-9][0-9]*'; then
                    DB_MONGO_CONNECTED=true
                    DB_MONGO_AUTH_MODE="PASSWORD"
                    DB_MONGO_USER="$user"
                    DB_MONGO_PW="$pw"
                    DB_MONGO_AUTH_DB="$db"
                    echo "  [OK] MongoDB 계정 인증 성공."
                    break
                fi
                echo "  [ERROR] 로그인 실패. 다시 입력하거나 q로 건너뛰세요."
            done
        fi
    fi
}

_selected_csv() {
    local out="" pair
    for pair in \
        "Apache:$SVC_WEB_APACHE" "Nginx:$SVC_WEB_NGINX" \
        "Tomcat:$SVC_WAS_TOMCAT" "JBoss:$SVC_WAS_JBOSS" "JEUS:$SVC_WAS_JEUS" \
        "MySQL:$SVC_DB_MYSQL" "PostgreSQL:$SVC_DB_POSTGRES" "MongoDB:$SVC_DB_MONGO" "Docker:$SVC_DOCKER"; do
        [ "${pair##*:}" = true ] && out+="${pair%%:*},"
    done
    printf '%s' "${out%,}"
}

_selected_docker_csv() {
    local out="" i
    for i in "${!DOCKER_CIDS[@]}"; do
        [ "${DOCKER_SELECTED[$i]}" = true ] || continue
        out+="${DOCKER_CIDS[$i]:0:12}:${DOCKER_NAMES[$i]}:${DOCKER_SERVICES[$i]};"
    done
    printf '%s' "${out%;}"
}

# 서비스 자동 탐지 -> 사용자 선택 -> 선택된 DB 인증 준비
# 이 단계는 보안 판정이 아니라 '점검 대상/접속 가능 여부' 수집 단계이다.
detect_target_services
show_target_services
select_target_services
setup_db_auth

# ------------------------------------------------------------------------------
# XML header / system information
# ------------------------------------------------------------------------------
HOSTNAME_VALUE="$(hostname 2>/dev/null || echo UNKNOWN)"
KERNEL_VALUE="$(uname -a 2>/dev/null || echo UNKNOWN)"
OS_VERSION_VALUE="$( (grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | head -n1 | cut -d= -f2- | sed 's/^"//;s/"$//') || true )"
[ -z "$OS_VERSION_VALUE" ] && OS_VERSION_VALUE="UNKNOWN"
CHECK_TIME="$(date '+%Y%m%d %H%M%S')"

cat > "$OUT_FILE" <<EOF_XML
<?xml version="1.0" encoding="UTF-8"?>
<EVIDENCE version="$VERSION">
  <SYSTEM>
    <CHECK_TIME>$(xml_escape "$CHECK_TIME")</CHECK_TIME>
    <HOSTNAME>$(xml_escape "$HOSTNAME_VALUE")</HOSTNAME>
    <KERNEL>$(xml_escape "$KERNEL_VALUE")</KERNEL>
    <OS_TYPE>$(xml_escape "$OS_TYPE")</OS_TYPE>
    <OS_VERSION>$(xml_escape "$OS_VERSION_VALUE")</OS_VERSION>
    <SELECTED_SERVICES>$(xml_escape "$(_selected_csv)")</SELECTED_SERVICES>
    <DOCKER_SELECTED_CONTAINERS>$(xml_escape "$(_selected_docker_csv)")</DOCKER_SELECTED_CONTAINERS>
    <DB_MYSQL_AUTH>$(xml_escape "${DB_MYSQL_CONNECTED}|${DB_MYSQL_AUTH_MODE}")</DB_MYSQL_AUTH>
    <DB_POSTGRES_AUTH>$(xml_escape "${DB_PG_CONNECTED}|${DB_PG_AUTH_MODE}")</DB_POSTGRES_AUTH>
    <DB_MONGO_AUTH>$(xml_escape "${DB_MONGO_CONNECTED}|${DB_MONGO_AUTH_MODE}")</DB_MONGO_AUTH>
  </SYSTEM>
EOF_XML

# ==============================================================================
# U-001 관리자계정 외 su 명령어 제한
# ==============================================================================
collect_u001() {
    begin_item "U-001" "관리자계정 외 su 명령어 제한"

    write_field "pam_su_file_exists" "$( [ -f "$CONF_PAM_SU" ] && echo true || echo false )" "$CONF_PAM_SU"
    if [ -f "$CONF_PAM_SU" ]; then
        local active_pam_wheel
        active_pam_wheel="$(grep -E '^[[:space:]]*[^#].*pam_wheel\.so' "$CONF_PAM_SU" 2>/dev/null || true)"
        write_field "pam_wheel_enabled" "$( [ -n "$active_pam_wheel" ] && echo true || echo false )" "$CONF_PAM_SU"
        while IFS= read -r line; do
            [ -n "$line" ] && write_field "pam_wheel_line" "$line" "$CONF_PAM_SU"
        done <<< "$active_pam_wheel"
    else
        write_field "pam_wheel_enabled" "false" "$CONF_PAM_SU"
    fi

    local su_count=0
    local seen=""
    for su_path in "${CMD_SU_PATHS[@]}"; do
        [ -n "$su_path" ] || continue
        local real_path
        real_path="$(readlink -f "$su_path" 2>/dev/null || printf '%s' "$su_path")"
        if [[ " $seen " == *" $real_path "* ]]; then
            continue
        fi
        seen+=" $real_path"
        if [ -f "$su_path" ]; then
            su_count=$((su_count + 1))
            local mode owner group
            mode="$(stat -Lc '%a' "$su_path" 2>/dev/null || echo UNKNOWN)"
            owner="$(stat -Lc '%U' "$su_path" 2>/dev/null || echo UNKNOWN)"
            group="$(stat -Lc '%G' "$su_path" 2>/dev/null || echo UNKNOWN)"
            write_field "su_file" "$real_path|$mode|$owner|$group" "$su_path" "path|mode|owner|group"
        fi
    done
    write_field "su_file_count" "$su_count" "su binaries"

    if [ -f /etc/group ]; then
        grep -E '^(wheel|root|su):' /etc/group 2>/dev/null | while IFS= read -r line; do
            [ -n "$line" ] && write_field "core_group" "$line" "/etc/group"
        done
        awk -F: '$3 >= 1000 {print}' /etc/group 2>/dev/null | while IFS= read -r line; do
            [ -n "$line" ] && write_field "normal_group" "$line" "/etc/group"
        done
    fi

    end_item
}

# ==============================================================================
# U-002 계정 잠금 임계값 설정
# ==============================================================================
collect_u002() {
    begin_item "U-002" "계정 잠금 임계값 설정"

    local module_count=0
    for pam_file in "${OS_PAM_AUTH_FILES[@]}"; do
        write_field "pam_file_exists" "$( [ -f "$pam_file" ] && echo true || echo false )" "$pam_file"
        if [ -f "$pam_file" ]; then
            local lines
            lines="$(grep -E -i 'pam_tally\.so|pam_tally2\.so|pam_faillock\.so' "$pam_file" 2>/dev/null | grep -v -E '^[[:space:]]*#' || true)"
            while IFS= read -r line; do
                [ -n "$line" ] || continue
                module_count=$((module_count + 1))
                write_field "lock_module_line" "$line" "$pam_file"
                local deny
                deny="$(printf '%s\n' "$line" | grep -o -E 'deny[[:space:]]*=[[:space:]]*[0-9]+' | head -n1 | grep -o -E '[0-9]+' || true)"
                [ -n "$deny" ] && write_field "pam_deny_value" "$deny" "$pam_file"
            done <<< "$lines"
        fi
    done
    write_field "lock_module_count" "$module_count" "PAM"

    write_field "faillock_file_exists" "$( [ -f "$CONF_FAILLOCK" ] && echo true || echo false )" "$CONF_FAILLOCK"
    if [ -f "$CONF_FAILLOCK" ]; then
        local deny unlock
        deny="$(grep -E -i '^[[:space:]]*deny[[:space:]]*=' "$CONF_FAILLOCK" 2>/dev/null | tail -n1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}')"
        unlock="$(grep -E -i '^[[:space:]]*unlock_time[[:space:]]*=' "$CONF_FAILLOCK" 2>/dev/null | tail -n1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}')"
        write_field "faillock_deny_value" "${deny:-NOT_SET}" "$CONF_FAILLOCK"
        write_field "faillock_unlock_time" "${unlock:-NOT_SET}" "$CONF_FAILLOCK"
    else
        write_field "faillock_deny_value" "FILE_NOT_FOUND" "$CONF_FAILLOCK"
        write_field "faillock_unlock_time" "FILE_NOT_FOUND" "$CONF_FAILLOCK"
    fi

    end_item
}

# ==============================================================================
# U-003 Session Timeout 설정
# ==============================================================================
collect_u003() {
    begin_item "U-003" "Session Timeout 설정"

    write_field "profile_exists" "$( [ -f "$CONF_PROFILE" ] && echo true || echo false )" "$CONF_PROFILE"
    if [ -f "$CONF_PROFILE" ]; then
        local line val
        line="$(grep -E -i '^[^#]*(TMOUT|TIMEOUT)[[:space:]]*=' "$CONF_PROFILE" 2>/dev/null | tail -n1 || true)"
        val="$(printf '%s\n' "$line" | grep -o -E '[0-9]+' | head -n1 || true)"
        write_field "global_timeout_line" "${line:-NOT_SET}" "$CONF_PROFILE"
        write_field "global_timeout_value" "${val:-NOT_SET}" "$CONF_PROFILE"
    else
        write_field "global_timeout_line" "FILE_NOT_FOUND" "$CONF_PROFILE"
        write_field "global_timeout_value" "FILE_NOT_FOUND" "$CONF_PROFILE"
    fi

    if [ -f "$CONF_PASSWD" ]; then
        while IFS=: read -r user _ _ _ _ home shell; do
            if [[ "$shell" == *"/bash"* ]] || [[ "$shell" == *"/sh"* ]]; then
                [ -d "$home" ] || continue
                for rc_file in "$home/.bash_profile" "$home/.bashrc" "$home/.profile"; do
                    [ -f "$rc_file" ] || continue
                    local u_line u_val
                    u_line="$(grep -E -i '^[^#]*(TMOUT|TIMEOUT)[[:space:]]*=' "$rc_file" 2>/dev/null | tail -n1 || true)"
                    [ -n "$u_line" ] || continue
                    u_val="$(printf '%s\n' "$u_line" | grep -o -E '[0-9]+' | head -n1 || true)"
                    write_field "user_timeout" "$user|$rc_file|${u_val:-NOT_SET}" "$rc_file" "user|file|value"
                done
            fi
        done < "$CONF_PASSWD"
    fi

    local csh_installed=false
    if grep -q -E '/csh$|/tcsh$' /etc/shells 2>/dev/null || command -v csh >/dev/null 2>&1; then
        csh_installed=true
    fi
    write_field "csh_installed" "$csh_installed" "/etc/shells"

    local csh_file_count=0
    if [ "$csh_installed" = true ]; then
        for csh_file in "$CONF_CSH_LOGIN" "$CONF_CSH_CSHRC"; do
            [ -n "$csh_file" ] || continue
            if [ -f "$csh_file" ]; then
                csh_file_count=$((csh_file_count + 1))
                local c_line c_val
                c_line="$(grep -i '^[^#]*autologout' "$csh_file" 2>/dev/null | tail -n1 || true)"
                c_val="$(printf '%s\n' "$c_line" | grep -o -E '[0-9]+' | head -n1 || true)"
                write_field "csh_autologout" "$csh_file|${c_val:-NOT_SET}" "$csh_file" "file|value"
            fi
        done
    fi
    write_field "csh_config_file_count" "$csh_file_count" "csh configuration"

    end_item
}

# ==============================================================================
# U-004 비밀번호 관리정책 설정
# ==============================================================================
collect_u004() {
    begin_item "U-004" "비밀번호 관리정책 설정"

    local pwq_line="" pwq_source=""
    for pam_file in "${OS_PAM_AUTH_FILES[@]}"; do
        [ -f "$pam_file" ] || continue
        pwq_line="$(grep -E 'pam_pwquality\.so|pam_cracklib\.so' "$pam_file" 2>/dev/null | grep -v -E '^[[:space:]]*#' | head -n1 || true)"
        if [ -n "$pwq_line" ]; then
            pwq_source="$pam_file"
            break
        fi
    done
    write_field "pwquality_module_present" "$( [ -n "$pwq_line" ] && echo true || echo false )" "${pwq_source:-PAM}"
    [ -n "$pwq_line" ] && write_field "pwquality_module_line" "$pwq_line" "$pwq_source"

    get_pwq_value() {
        local key="$1" val=""
        if [ -n "$pwq_line" ]; then
            val="$(printf '%s\n' "$pwq_line" | grep -o -E "$key=[-0-9]+" | head -n1 | cut -d= -f2 || true)"
        fi
        if [ -z "$val" ] && [ -f "$CONF_PWQUALITY" ]; then
            val="$(grep -E "^[[:space:]]*$key[[:space:]]*=" "$CONF_PWQUALITY" 2>/dev/null | tail -n1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}')"
        fi
        printf '%s' "${val:-NOT_SET}"
    }

    for key in minlen minclass dcredit ucredit lcredit ocredit; do
        write_field "$key" "$(get_pwq_value "$key")" "$CONF_PWQUALITY"
    done

    write_field "login_defs_exists" "$( [ -f "$CONF_LOGIN_DEFS" ] && echo true || echo false )" "$CONF_LOGIN_DEFS"
    if [ -f "$CONF_LOGIN_DEFS" ]; then
        local p_min p_max
        p_min="$(grep -E '^[[:space:]]*PASS_MIN_DAYS' "$CONF_LOGIN_DEFS" 2>/dev/null | tail -n1 | awk '{print $2}')"
        p_max="$(grep -E '^[[:space:]]*PASS_MAX_DAYS' "$CONF_LOGIN_DEFS" 2>/dev/null | tail -n1 | awk '{print $2}')"
        write_field "pass_min_days" "${p_min:-NOT_SET}" "$CONF_LOGIN_DEFS"
        write_field "pass_max_days" "${p_max:-NOT_SET}" "$CONF_LOGIN_DEFS"
    else
        write_field "pass_min_days" "FILE_NOT_FOUND" "$CONF_LOGIN_DEFS"
        write_field "pass_max_days" "FILE_NOT_FOUND" "$CONF_LOGIN_DEFS"
    fi

    local hist_line="" hist_source=""
    for pam_file in "${OS_PAM_AUTH_FILES[@]}"; do
        [ -f "$pam_file" ] || continue
        hist_line="$(grep 'pam_pwhistory\.so' "$pam_file" 2>/dev/null | grep -v -E '^[[:space:]]*#' | head -n1 || true)"
        if [ -n "$hist_line" ]; then
            hist_source="$pam_file"
            break
        fi
    done
    write_field "pwhistory_module_present" "$( [ -n "$hist_line" ] && echo true || echo false )" "${hist_source:-PAM}"
    [ -n "$hist_line" ] && write_field "pwhistory_module_line" "$hist_line" "$hist_source"

    local remember="" enforce="false"
    if [ -n "$hist_line" ]; then
        remember="$(printf '%s\n' "$hist_line" | grep -o -E 'remember=[0-9]+' | head -n1 | cut -d= -f2 || true)"
        printf '%s\n' "$hist_line" | grep -q 'enforce_for_root' && enforce=true
    fi
    if [ -z "$remember" ] && [ -f "$CONF_PWHISTORY" ]; then
        remember="$(grep -E '^[[:space:]]*remember[[:space:]]*=' "$CONF_PWHISTORY" 2>/dev/null | tail -n1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}')"
    fi
    if [ "$enforce" = false ] && [ -f "$CONF_PWHISTORY" ]; then
        grep -E -q '^[[:space:]]*enforce_for_root' "$CONF_PWHISTORY" 2>/dev/null && enforce=true
    fi
    write_field "pwhistory_remember" "${remember:-NOT_SET}" "$CONF_PWHISTORY"
    write_field "pwhistory_enforce_for_root" "$enforce" "$CONF_PWHISTORY"

    end_item
}

# ==============================================================================
# U-005 root 계정 원격접속 제한
# ==============================================================================
collect_u005() {
    begin_item "U-005" "root 계정 원격접속 제한(Telnet, SSH 등 원격접속)"

    local sshd_ps sshd_running=false
    sshd_ps="$(ps -ef 2>/dev/null | grep -E -i '[s]shd' || true)"
    [ -n "$sshd_ps" ] && sshd_running=true
    write_field "sshd_running" "$sshd_running" "process table"
    while IFS= read -r line; do
        [ -n "$line" ] && write_field "sshd_process" "$line" "ps -ef"
    done <<< "$sshd_ps"

    if [ "$sshd_running" = true ]; then
        local permit=""
        if command -v sshd >/dev/null 2>&1; then
            permit="$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin" {print $2; exit}' || true)"
        fi
        write_field "permitrootlogin" "${permit:-NOT_SET}" "sshd -T"
    else
        write_field "permitrootlogin" "NOT_APPLICABLE" "sshd -T"
    fi

    end_item
}

# ==============================================================================
# U-006 불필요한 시스템 계정 Shell 제한 여부
# ==============================================================================
collect_u006() {
    begin_item "U-006" "불필요한 시스템 계정 Shell 제한 여부"

    write_field "passwd_file_exists" "$( [ -f "$CONF_PASSWD" ] && echo true || echo false )" "$CONF_PASSWD"
    if [ -f "$CONF_PASSWD" ]; then
        awk -F: '$1 ~ /^(adm|sync|shutdown|halt|news|operator|games|gopher|nobody|nfsnobody|squid|guest|ftp)$/ {print $1"|"$7}' "$CONF_PASSWD" 2>/dev/null |
        while IFS= read -r value; do
            [ -n "$value" ] && write_field "system_account_shell" "$value" "$CONF_PASSWD" "account|shell"
        done
    fi

    end_item
}

# ==============================================================================
# U-007 패스워드 암호화 저장
# ==============================================================================
collect_u007() {
    begin_item "U-007" "패스워드 암호화 저장"

    write_field "passwd_file_exists" "$( [ -f "$CONF_PASSWD" ] && echo true || echo false )" "$CONF_PASSWD"
    write_field "shadow_file_exists" "$( [ -f "$CONF_SHADOW" ] && echo true || echo false )" "$CONF_SHADOW"

    if [ -f "$CONF_PASSWD" ]; then
        awk -F: '$2 != "x" && $2 != "*" && $2 != "!" && $2 != "" {print $1}' "$CONF_PASSWD" 2>/dev/null |
        while IFS= read -r user; do
            [ -n "$user" ] && write_field "passwd_nonshadow_account" "$user" "$CONF_PASSWD"
        done
    fi

    if [ -f "$CONF_PASSWD" ] && [ -f "$CONF_SHADOW" ]; then
        awk -F: '$7 !~ /(nologin|false)$/ {print $1}' "$CONF_PASSWD" 2>/dev/null |
        while IFS= read -r user; do
            [ -n "$user" ] || continue
            local hash status
            hash="$(awk -F: -v u="$user" '$1==u {print $2; exit}' "$CONF_SHADOW" 2>/dev/null)"
            if [ -z "$hash" ]; then
                status="NP"
            elif [[ "$hash" == "!"* ]] || [[ "$hash" == "*"* ]]; then
                status="LK"
            else
                status="PS"
            fi
            write_field "active_account_password_status" "$user|$status" "$CONF_SHADOW" "account|status"
        done
    fi

    end_item
}

# ==============================================================================
# U-008 동일한 UID 금지
# ==============================================================================
collect_u008() {
    begin_item "U-008" "동일한 UID 금지"
    write_field "passwd_file_exists" "$( [ -f "$CONF_PASSWD" ] && echo true || echo false )" "$CONF_PASSWD"
    if [ -f "$CONF_PASSWD" ]; then
        awk -F: '{print $3"|"$1}' "$CONF_PASSWD" 2>/dev/null |
        while IFS= read -r value; do
            [ -n "$value" ] && write_field "uid_account" "$value" "$CONF_PASSWD" "uid|account"
        done
    fi
    end_item
}

# ==============================================================================
# U-009 root 이외의 UID가 0 금지
# ==============================================================================
collect_u009() {
    begin_item "U-009" "root 이외의 UID가 0 금지"
    write_field "passwd_file_exists" "$( [ -f "$CONF_PASSWD" ] && echo true || echo false )" "$CONF_PASSWD"
    if [ -f "$CONF_PASSWD" ]; then
        awk -F: '{print $3"|"$1}' "$CONF_PASSWD" 2>/dev/null |
        while IFS= read -r value; do
            [ -n "$value" ] && write_field "uid_account" "$value" "$CONF_PASSWD" "uid|account"
        done
    fi
    end_item
}

# ==============================================================================
# U-010 안전한 비밀번호 암호화 알고리즘 사용
# ==============================================================================
collect_u010() {
    begin_item "U-010" "안전한 비밀번호 암호화 알고리즘 사용"

    write_field "shadow_file_exists" "$( [ -f "$CONF_SHADOW" ] && echo true || echo false )" "$CONF_SHADOW"
    if [ -f "$CONF_SHADOW" ]; then
        awk -F: '$2 != "" && substr($2,1,1) != "!" && substr($2,1,1) != "*" {print $1"|"$2}' "$CONF_SHADOW" 2>/dev/null |
        while IFS='|' read -r user hash; do
            [ -n "$user" ] || continue
            local scheme="LEGACY_OR_UNKNOWN"
            if [[ "$hash" == \$* ]]; then
                scheme="$(printf '%s' "$hash" | cut -d'$' -f2)"
                [ -z "$scheme" ] && scheme="UNKNOWN"
            fi
            write_field "active_hash_scheme" "$user|$scheme" "$CONF_SHADOW" "account|scheme"
        done
    fi

    write_field "login_defs_exists" "$( [ -f "$CONF_LOGIN_DEFS" ] && echo true || echo false )" "$CONF_LOGIN_DEFS"
    if [ -f "$CONF_LOGIN_DEFS" ]; then
        local enc
        enc="$(grep -E '^[[:space:]]*ENCRYPT_METHOD' "$CONF_LOGIN_DEFS" 2>/dev/null | tail -n1 | awk '{print $2}')"
        write_field "encrypt_method" "${enc:-NOT_SET}" "$CONF_LOGIN_DEFS"
    else
        write_field "encrypt_method" "FILE_NOT_FOUND" "$CONF_LOGIN_DEFS"
    fi

    local pam_count=0
    for pam_file in "${OS_PAM_AUTH_FILES[@]}"; do
        [ -f "$pam_file" ] || continue
        local lines
        lines="$(grep -E -i '^[[:space:]]*password.*(pam_unix\.so|pam_yescrypt\.so)' "$pam_file" 2>/dev/null | grep -v -E '^[[:space:]]*#' || true)"
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            pam_count=$((pam_count + 1))
            write_field "pam_password_module_line" "$line" "$pam_file"
        done <<< "$lines"
    done
    write_field "pam_password_module_count" "$pam_count" "PAM"

    end_item
}


# ==============================================================================
# Common helpers for U-011 ~ U-100
# ==============================================================================
proc_active() {
    local pattern="$1"
    if ps -ef 2>/dev/null | grep -E -i "$pattern" | grep -v -E 'grep|collect_evidence' >/dev/null 2>&1; then
        printf 'true'
    else
        printf 'false'
    fi
}

cmd_exists() {
    command -v "$1" >/dev/null 2>&1 && printf 'true' || printf 'false'
}

write_path_stat() {
    local key="$1" path="$2"
    if [ -e "$path" ]; then
        local mode owner group ftype
        mode="$(stat -Lc '%a' "$path" 2>/dev/null || echo UNKNOWN)"
        owner="$(stat -Lc '%U' "$path" 2>/dev/null || echo UNKNOWN)"
        group="$(stat -Lc '%G' "$path" 2>/dev/null || echo UNKNOWN)"
        ftype="$(stat -Lc '%F' "$path" 2>/dev/null || echo UNKNOWN)"
        write_field "$key" "$path|true|$mode|$owner|$group|$ftype" "$path" "path|exists|mode|owner|group|type"
    else
        write_field "$key" "$path|false|NOT_SET|NOT_SET|NOT_SET|NOT_SET" "$path" "path|exists|mode|owner|group|type"
    fi
}

grep_noncomment() {
    local file="$1" pattern="$2"
    [ -f "$file" ] || return 0
    grep -E -i "$pattern" "$file" 2>/dev/null | grep -v -E '^[[:space:]]*#' || true
}

listening_ports() {
    if command -v ss >/dev/null 2>&1; then
        ss -lntup 2>/dev/null || true
    elif command -v netstat >/dev/null 2>&1; then
        netstat -lntup 2>/dev/null || true
    fi
}

port_active() {
    local port="$1"
    if listening_ports | grep -E -q "[:.]${port}[[:space:]]"; then printf 'true'; else printf 'false'; fi
}

detect_web() {
    write_field "apache_detected" "$SVC_WEB_APACHE_DETECTED" "service discovery"
    write_field "nginx_detected" "$SVC_WEB_NGINX_DETECTED" "service discovery"
    write_field "apache_selected" "$SVC_WEB_APACHE" "user selection"
    write_field "nginx_selected" "$SVC_WEB_NGINX" "user selection"
    # 기존 assessment 호환: *_active는 '이번 진단에서 활성 대상으로 선택됨'을 의미하도록 기록
    write_field "apache_active" "$SVC_WEB_APACHE" "selected target"
    write_field "nginx_active" "$SVC_WEB_NGINX" "selected target"
    [ "$SVC_WEB_APACHE" = true ] || [ "$SVC_WEB_NGINX" = true ]
}

detect_db() {
    write_field "mysql_detected" "$SVC_DB_MYSQL_DETECTED" "service discovery"
    write_field "postgres_detected" "$SVC_DB_POSTGRES_DETECTED" "service discovery"
    write_field "mongo_detected" "$SVC_DB_MONGO_DETECTED" "service discovery"
    write_field "mysql_selected" "$SVC_DB_MYSQL" "user selection"
    write_field "postgres_selected" "$SVC_DB_POSTGRES" "user selection"
    write_field "mongo_selected" "$SVC_DB_MONGO" "user selection"
    write_field "mysql_active" "$SVC_DB_MYSQL" "selected target"
    write_field "postgres_active" "$SVC_DB_POSTGRES" "selected target"
    write_field "mongo_active" "$SVC_DB_MONGO" "selected target"
    write_field "mysql_db_connected" "$DB_MYSQL_CONNECTED" "DB authentication"
    write_field "mysql_auth_mode" "$DB_MYSQL_AUTH_MODE" "DB authentication"
    write_field "postgres_db_connected" "$DB_PG_CONNECTED" "DB authentication"
    write_field "postgres_auth_mode" "$DB_PG_AUTH_MODE" "DB authentication"
    write_field "mongo_db_connected" "$DB_MONGO_CONNECTED" "DB authentication"
    write_field "mongo_auth_mode" "$DB_MONGO_AUTH_MODE" "DB authentication"
    [ "$SVC_DB_MYSQL" = true ] || [ "$SVC_DB_POSTGRES" = true ] || [ "$SVC_DB_MONGO" = true ]
}

detect_was() {
    write_field "tomcat_detected" "$SVC_WAS_TOMCAT_DETECTED" "service discovery"
    write_field "jboss_detected" "$SVC_WAS_JBOSS_DETECTED" "service discovery"
    write_field "jeus_detected" "$SVC_WAS_JEUS_DETECTED" "service discovery"
    write_field "tomcat_selected" "$SVC_WAS_TOMCAT" "user selection"
    write_field "jboss_selected" "$SVC_WAS_JBOSS" "user selection"
    write_field "jeus_selected" "$SVC_WAS_JEUS" "user selection"
    write_field "tomcat_active" "$SVC_WAS_TOMCAT" "selected target"
    write_field "jboss_active" "$SVC_WAS_JBOSS" "selected target"
    write_field "jeus_active" "$SVC_WAS_JEUS" "selected target"
    [ "$SVC_WAS_TOMCAT" = true ] || [ "$SVC_WAS_JBOSS" = true ] || [ "$SVC_WAS_JEUS" = true ]
}

write_matching_lines() {
    local key="$1" file="$2" pattern="$3"
    if [ -f "$file" ]; then
        local found=false
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            found=true
            write_field "$key" "$line" "$file"
        done < <(grep_noncomment "$file" "$pattern")
        [ "$found" = true ] || write_field "$key" "NOT_SET" "$file"
    else
        write_field "$key" "FILE_NOT_FOUND" "$file"
    fi
}

# ------------------------------------------------------------------------------
# U-011 ~ U-025 Service management
# ------------------------------------------------------------------------------
collect_u011() {
    begin_item "U-011" "DoS 공격에 취약한 서비스 비활성화"
    for svc in echo discard daytime chargen; do
        local p=""
        case "$svc" in echo) p=7;; discard) p=9;; daytime) p=13;; chargen) p=19;; esac
        write_field "legacy_service" "$svc|$(port_active "$p")" "listening ports" "service|active"
    done
    end_item
}

collect_u012() {
    begin_item "U-012" "불필요한 서비스 비활성화"
    write_field "smtp_active" "$(port_active 25)" "25/tcp"
    write_field "dns_active" "$( [ "$(port_active 53)" = true ] || listening_ports | grep -qE '[:.]53[[:space:]]' && echo true || echo false )" "53/tcp,udp"
    write_field "snmp_active" "$( listening_ports | grep -qE '[:.]161[[:space:]]' && echo true || echo false )" "161/udp"
    write_field "nfs_active" "$(proc_active 'nfsd|rpc\.mountd|rpcbind')" "process table"
    end_item
}

collect_u013() {
    begin_item "U-013" "취약한 서비스 비활성화"
    for spec in "finger|79" "exec|512" "login|513" "shell|514" "tftp|69"; do
        local svc="${spec%%|*}" p="${spec##*|}"
        write_field "vulnerable_service" "$svc|$(port_active "$p")" "listening ports" "service|active"
    done
    write_field "autofs_active" "$(proc_active 'automountd|autofs')" "process table"
    write_field "rpc_active" "$(proc_active 'rpcbind|rpc\.statd|rpc\.mountd')" "process table"
    end_item
}

collect_u014() {
    begin_item "U-014" "Cron 관련 파일 소유자 및 권한 설정"
    for p in /usr/bin/crontab /usr/bin/at /etc/cron.allow /etc/cron.deny /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        write_path_stat "cron_path" "$p"
    done
    for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [ -d "$d" ] || continue
        find "$d" -maxdepth 1 -type f 2>/dev/null | head -n 200 | while IFS= read -r p; do write_path_stat "cron_member" "$p"; done
    done
    end_item
}

collect_u015() {
    begin_item "U-015" "암호화되지 않는 FTP 서비스 비활성화"
    write_field "ftp_active" "$(proc_active 'vsftpd|proftpd|pure-ftpd|in\.ftpd')" "process table"
    write_field "ftp_port21_active" "$(port_active 21)" "21/tcp"
    end_item
}

collect_u016() {
    begin_item "U-016" "ftpusers 파일 소유자 및 권한 설정"
    local ftp="$(proc_active 'vsftpd|proftpd|pure-ftpd|in\.ftpd')"
    write_field "ftp_active" "$ftp" "process table"
    for p in /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list; do write_path_stat "ftpusers_file" "$p"; done
    end_item
}

collect_u017() {
    begin_item "U-017" "ftpusers 파일 설정"
    local ftp="$(proc_active 'vsftpd|proftpd|pure-ftpd|in\.ftpd')"
    write_field "ftp_active" "$ftp" "process table"
    for p in /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list; do
        if [ -f "$p" ]; then
            write_field "ftp_root_entry" "$p|$(grep -E -q '^[[:space:]]*root[[:space:]]*$' "$p" && echo true || echo false)" "$p" "file|root_listed"
        fi
    done
    end_item
}

collect_u018() {
    begin_item "U-018" "공유 서비스에 대한 익명 접근 제한 설정"
    write_field "ftp_active" "$(proc_active 'vsftpd|proftpd|pure-ftpd|in\.ftpd')" "process table"
    write_matching_lines "vsftpd_anonymous" /etc/vsftpd.conf '^[[:space:]]*(anonymous_enable|anon_upload_enable|anon_mkdir_write_enable)'
    write_field "nfs_active" "$(proc_active 'nfsd|rpc\.mountd')" "process table"
    write_matching_lines "nfs_export" /etc/exports '.+'
    local smb="/etc/samba/smb.conf"
    write_matching_lines "samba_guest" "$smb" 'guest[[:space:]]+ok|map[[:space:]]+to[[:space:]]+guest'
    end_item
}

collect_u019() {
    begin_item "U-019" "암호화된 원격접속 서비스 사용 및 기본 포트 변경"
    write_field "telnet_active" "$( [ "$(port_active 23)" = true ] || [ "$(proc_active 'telnetd|in\.telnetd')" = true ] && echo true || echo false )" "23/tcp"
    local ssh="$(proc_active '(^|/)sshd([[:space:]]|$)')"
    write_field "ssh_active" "$ssh" "process table"
    if [ "$ssh" = true ] && command -v sshd >/dev/null 2>&1; then
        local ports root
        ports="$(sshd -T 2>/dev/null | awk 'tolower($1)=="port"{print $2}' | tr '\n' ',' | sed 's/,$//' || true)"
        root="$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print $2;exit}' || true)"
        write_field "ssh_ports" "${ports:-NOT_SET}" "sshd -T"
        write_field "permitrootlogin" "${root:-NOT_SET}" "sshd -T"
    else
        write_field "ssh_ports" "NOT_APPLICABLE" "sshd -T"
        write_field "permitrootlogin" "NOT_APPLICABLE" "sshd -T"
    fi
    end_item
}

collect_u020() {
    begin_item "U-020" "NFS 접근통제"
    local nfs="$(proc_active 'nfsd|rpc\.mountd')"
    write_field "nfs_active" "$nfs" "process table"
    write_matching_lines "nfs_export" /etc/exports '.+'
    end_item
}

collect_u021() {
    begin_item "U-021" "NFS 설정파일 접근권한"
    write_field "nfs_active" "$(proc_active 'nfsd|rpc\.mountd')" "process table"
    write_path_stat "exports_file" /etc/exports
    end_item
}

collect_u022() {
    begin_item "U-022" "SMTP expn, vrfy 명령어 제한"
    local smtp="$( [ "$(port_active 25)" = true ] || [ "$(proc_active 'sendmail|postfix/master')" = true ] && echo true || echo false )"
    write_field "smtp_active" "$smtp" "process/25tcp"
    write_matching_lines "sendmail_privacy" /etc/mail/sendmail.cf 'PrivacyOptions'
    write_matching_lines "postfix_restriction" /etc/postfix/main.cf 'smtpd_.*restrictions|disable_vrfy_command'
    end_item
}

collect_u023() {
    begin_item "U-023" "DNS Zone Transfer 설정"
    local dns="$( [ "$(port_active 53)" = true ] || [ "$(proc_active 'named|bind9')" = true ] && echo true || echo false )"
    write_field "dns_active" "$dns" "process/53"
    for p in /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options /etc/bind/named.conf.local; do
        [ -f "$p" ] && write_matching_lines "allow_transfer" "$p" 'allow-transfer'
    done
    end_item
}

collect_u024() {
    begin_item "U-024" "SNMP 서비스 Community String의 복잡성 설정"
    local snmp="$( [ "$(proc_active 'snmpd')" = true ] && echo true || echo false )"
    write_field "snmp_active" "$snmp" "process table"
    write_matching_lines "snmp_community" /etc/snmp/snmpd.conf 'rocommunity|rwcommunity|com2sec'
    end_item
}

collect_u025() {
    begin_item "U-025" "sudo 명령어 접근 관리"
    write_path_stat "sudoers_file" /etc/sudoers
    end_item
}

# ------------------------------------------------------------------------------
# U-026 ~ U-036 Web
# ------------------------------------------------------------------------------
collect_u026() {
    begin_item "U-026" "웹 서비스 디렉터리 쓰기 권한 관리"
    detect_web || true
    for p in /etc/apache2 /etc/httpd /var/www/html /usr/share/nginx/html /etc/nginx; do
        [ -e "$p" ] && write_path_stat "web_directory" "$p"
    done
    end_item
}
collect_u027() {
    begin_item "U-027" "웹 서비스 소스/설정파일 권한 관리"
    detect_web || true
    for p in /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf /etc/nginx/nginx.conf; do write_path_stat "web_config" "$p"; done
    for p in /var/www/html /usr/share/nginx/html; do [ -d "$p" ] && find "$p" -maxdepth 2 -type f 2>/dev/null | head -n 200 | while read -r f; do write_path_stat "web_source" "$f"; done; done
    end_item
}
collect_u028() {
    begin_item "U-028" "웹 서비스 파일 업로드 및 다운로드 용량 제한"
    detect_web || true
    for p in /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf /etc/nginx/nginx.conf; do
        [ -f "$p" ] && write_matching_lines "upload_limit" "$p" 'LimitRequestBody|client_max_body_size'
    done
    end_item
}
collect_u029() {
    begin_item "U-029" "웹 서비스 상위 디렉터리 접근 금지"
    detect_web || true
    for d in /etc/apache2 /etc/httpd /etc/nginx; do
        [ -d "$d" ] && grep -R -E -i '^[[:space:]]*(AllowOverride|alias)[[:space:]]' "$d" 2>/dev/null | head -n 200 | while IFS= read -r l; do write_field "dir_access_setting" "$l" "$d"; done
    done
    end_item
}
collect_u030() {
    begin_item "U-030" "웹 서비스 정보 숨김"
    detect_web || true
    for d in /etc/apache2 /etc/httpd /etc/nginx; do
        [ -d "$d" ] && grep -R -E -i '^[[:space:]]*(ServerTokens|ServerSignature|server_tokens)[[:space:]]' "$d" 2>/dev/null | head -n 100 | while IFS= read -r l; do write_field "banner_setting" "$l" "$d"; done
    done
    end_item
}
collect_u031() {
    begin_item "U-031" "웹 서비스 링크 사용금지"
    detect_web || true
    for d in /etc/apache2 /etc/httpd; do
        [ -d "$d" ] && grep -R -E -i '^[[:space:]]*Options.*(FollowSymLinks|SymLinksIfOwnerMatch|All)' "$d" 2>/dev/null | head -n 200 | while IFS= read -r l; do write_field "symlink_setting" "$l" "$d"; done
    done
    end_item
}
collect_u032() {
    begin_item "U-032" "웹 서비스 CGI 스크립트 실행 제한"
    detect_web || true
    for d in /etc/apache2 /etc/httpd; do
        [ -d "$d" ] && grep -R -E -i 'ScriptAlias|ExecCGI' "$d" 2>/dev/null | head -n 200 | while IFS= read -r l; do write_field "cgi_setting" "$l" "$d"; done
    done
    end_item
}
collect_u033() {
    begin_item "U-033" "웹 서비스 디렉터리 리스팅 제거"
    detect_web || true
    for d in /etc/apache2 /etc/httpd /etc/nginx; do
        [ -d "$d" ] && grep -R -E -i '^[[:space:]]*Options.*Indexes|^[[:space:]]*autoindex[[:space:]]+on' "$d" 2>/dev/null | head -n 200 | while IFS= read -r l; do write_field "listing_setting" "$l" "$d"; done
    done
    end_item
}
collect_u034() {
    begin_item "U-034" "웹 서비스 영역의 분리"
    detect_web || true
    for d in /etc/apache2 /etc/httpd /etc/nginx; do
        [ -d "$d" ] && grep -R -E -i '^[[:space:]]*(DocumentRoot|root)[[:space:]]+' "$d" 2>/dev/null | head -n 100 | while IFS= read -r l; do write_field "document_root_setting" "$l" "$d"; done
    done
    end_item
}
collect_u035() {
    begin_item "U-035" "웹 서비스 불필요한 파일 제거"
    detect_web || true
    for p in /var/www/html/manual /usr/share/doc/apache2-doc /usr/share/nginx/html/50x.html; do write_field "default_web_artifact" "$p|$( [ -e "$p" ] && echo true || echo false )" "$p" "path|exists"; done
    end_item
}
collect_u036() {
    begin_item "U-036" "웹 서비스 데몬 관리"
    detect_web || true
    ps -eo user=,comm=,args= 2>/dev/null | grep -E -i '(apache2|httpd|nginx)' | grep -v grep | head -n 100 | while IFS= read -r l; do write_field "web_process" "$l" "ps"; done
    end_item
}

# ------------------------------------------------------------------------------
# U-037 ~ U-051 File/patch/log/backup
# ------------------------------------------------------------------------------
collect_u037() {
    begin_item "U-037" "UMASK 설정 관리"
    write_field "current_umask" "$(umask)" "shell"
    local v="$(grep -E '^[[:space:]]*UMASK[[:space:]]+' /etc/login.defs 2>/dev/null | tail -n1 | awk '{print $2}' || true)"
    write_field "login_defs_umask" "${v:-NOT_SET}" "/etc/login.defs"
    end_item
}
collect_u038() {
    begin_item "U-038" "/etc/(x)inetd.conf 파일 소유자 및 권한 설정"
    write_path_stat "inetd_file" /etc/inetd.conf
    write_path_stat "xinetd_dir" /etc/xinetd.d
    end_item
}
collect_u039() { begin_item "U-039" "/etc/shadow 파일 소유자 및 권한 설정"; write_path_stat "target_file" /etc/shadow; end_item; }
collect_u040() { begin_item "U-040" "/etc/hosts 파일 소유자 및 권한 설정"; write_path_stat "target_file" /etc/hosts; end_item; }
collect_u041() {
    begin_item "U-041" "/etc/syslog.conf 파일 소유자 및 권한 설정"
    for p in /etc/syslog.conf /etc/rsyslog.conf; do [ -e "$p" ] && write_path_stat "target_file" "$p"; done
    end_item
}
collect_u042() {
    begin_item "U-042" "사용자 홈디렉터리 내 환경변수 파일 소유자 및 권한 설정"
    [ -f /etc/passwd ] && while IFS=: read -r user _ uid _ _ home shell; do
        [ -d "$home" ] || continue
        for f in .profile .bash_profile .bashrc .cshrc .login .kshrc; do [ -e "$home/$f" ] && write_path_stat "env_file" "$home/$f"; done
    done < /etc/passwd
    end_item
}
collect_u043() { begin_item "U-043" "root 계정 환경변수의 'PATH' 값 보안설정"; write_field "root_path" "$PATH" "current environment"; end_item; }
collect_u044() {
    begin_item "U-044" "접속 IP 및 포트 제한"
    write_matching_lines "hosts_allow" /etc/hosts.allow '.+'
    write_matching_lines "hosts_deny" /etc/hosts.deny '.+'
    write_field "firewall_tool" "$( command -v nft >/dev/null 2>&1 && echo nft || command -v firewall-cmd >/dev/null 2>&1 && echo firewalld || command -v ufw >/dev/null 2>&1 && echo ufw || echo NOT_FOUND )" "system"
    end_item
}
collect_u045() { begin_item "U-045" "/etc/passwd 파일 소유자 및 권한 설정"; write_path_stat "target_file" /etc/passwd; end_item; }
collect_u046() { begin_item "U-046" "/etc/services 파일 소유자 및 권한 설정"; write_path_stat "target_file" /etc/services; end_item; }
collect_u047() {
    begin_item "U-047" "보안에 취약하지 않은 버전의 OS를 사용"
    write_field "os_release" "$(cat /etc/os-release 2>/dev/null || true)" "/etc/os-release"
    write_field "kernel_release" "$(uname -r 2>/dev/null || true)" "uname -r"
    end_item
}
collect_u048() {
    begin_item "U-048" "서비스 최신 보안 패치 적용 여부(DNS, SMTP 등)"
    write_field "dns_active" "$( [ "$(port_active 53)" = true ] && echo true || echo false )" "53"
    write_field "smtp_active" "$( [ "$(port_active 25)" = true ] && echo true || echo false )" "25"
    write_field "named_version" "$(named -v 2>/dev/null || echo NOT_FOUND)" "named -v"
    write_field "sendmail_version" "$(sendmail -d0.1 -bv root 2>/dev/null | head -n1 || echo NOT_FOUND)" "sendmail"
    write_field "postfix_version" "$(postconf mail_version 2>/dev/null || echo NOT_FOUND)" "postconf"
    end_item
}
collect_u049() {
    begin_item "U-049" "정책에 따른 시스템 로깅 설정"
    write_field "rsyslog_active" "$(proc_active 'rsyslogd|syslog-ng')" "process table"
    write_path_stat "rsyslog_conf" /etc/rsyslog.conf
    write_path_stat "syslog_conf" /etc/syslog.conf
    end_item
}
collect_u050() {
    begin_item "U-050" "로그 디렉터리 소유자 및 권한 설정"
    for p in /var/log /var/log/wtmp /var/log/lastlog /var/log/btmp /etc/rsyslog.conf /etc/syslog.conf; do write_path_stat "log_path" "$p"; done
    end_item
}
collect_u051() {
    begin_item "U-051" "중요데이터 백업 여부"
    write_field "backup_interview_required" "true" "manual/interview"
    end_item
}

# ------------------------------------------------------------------------------
# U-052 ~ U-059 Database
# ------------------------------------------------------------------------------
collect_db_common() {
    detect_db || true

    # 선택된 Host DB 프로세스 증적
    if [ "$SVC_DB_MYSQL" = true ]; then
        ps -ef 2>/dev/null | grep -E -i 'mysqld|mariadbd' | grep -v grep | head -n 50 | while IFS= read -r l; do write_field "db_process" "$l" "ps"; done
    fi
    if [ "$SVC_DB_POSTGRES" = true ]; then
        ps -ef 2>/dev/null | grep -E -i 'postgres|postmaster' | grep -v grep | head -n 50 | while IFS= read -r l; do write_field "db_process" "$l" "ps"; done
    fi
    if [ "$SVC_DB_MONGO" = true ]; then
        ps -ef 2>/dev/null | grep -E -i 'mongod' | grep -v grep | head -n 50 | while IFS= read -r l; do write_field "db_process" "$l" "ps"; done
    fi

    # 인증 성공 시 DB 내부 설정/계정 정보를 Evidence로 추가 수집 (판정은 Python에서 수행)
    if [ "$SVC_DB_MYSQL" = true ] && [ "$DB_MYSQL_CONNECTED" = true ]; then
        mysql_query "SELECT User,Host,plugin FROM mysql.user" 2>/dev/null | head -n 200 | while IFS= read -r l; do [ -n "$l" ] && write_field "mysql_user_record" "$l" "mysql.user" "user|host|plugin"; done
        mysql_query "SHOW VARIABLES LIKE 'default_password_lifetime'" 2>/dev/null | while IFS= read -r l; do [ -n "$l" ] && write_field "mysql_password_variable" "$l" "SHOW VARIABLES"; done
        mysql_query "SHOW VARIABLES LIKE 'validate_password%'" 2>/dev/null | head -n 100 | while IFS= read -r l; do [ -n "$l" ] && write_field "mysql_password_variable" "$l" "SHOW VARIABLES"; done
        mysql_query "SHOW VARIABLES WHERE Variable_name IN ('general_log','slow_query_log','log_output','max_connections','max_user_connections')" 2>/dev/null | head -n 100 | while IFS= read -r l; do [ -n "$l" ] && write_field "mysql_runtime_variable" "$l" "SHOW VARIABLES"; done
    fi

    if [ "$SVC_DB_POSTGRES" = true ] && [ "$DB_PG_CONNECTED" = true ]; then
        pg_query "SELECT rolname||'|'||rolsuper||'|'||rolcanlogin FROM pg_roles ORDER BY rolname" 2>/dev/null | head -n 200 | while IFS= read -r l; do [ -n "$l" ] && write_field "postgres_role_record" "$l" "pg_roles" "role|superuser|canlogin"; done
        for q in "SHOW password_encryption" "SHOW log_statement" "SHOW max_connections" "SHOW hba_file" "SHOW config_file"; do
            pg_query "$q" 2>/dev/null | head -n 20 | while IFS= read -r l; do [ -n "$l" ] && write_field "postgres_runtime_setting" "$q|$l" "PostgreSQL SHOW" "query|value"; done
        done
    fi

    if [ "$SVC_DB_MONGO" = true ] && [ "$DB_MONGO_CONNECTED" = true ]; then
        mongo_query 'JSON.stringify(db.getSiblingDB("admin").runCommand({usersInfo:1}))' 2>/dev/null | head -c 20000 | while IFS= read -r l; do [ -n "$l" ] && write_field "mongo_user_info" "$l" "admin.usersInfo"; done
        mongo_query 'JSON.stringify(db.adminCommand({getCmdLineOpts:1}).parsed)' 2>/dev/null | head -c 20000 | while IFS= read -r l; do [ -n "$l" ] && write_field "mongo_runtime_setting" "$l" "getCmdLineOpts"; done
    fi

    # 선택된 Docker 컨테이너 목록 자체도 DB/WAS/Web 후속 확장을 위해 공통 증적으로 남김
    if [ "$SVC_DOCKER" = true ]; then
        local i
        for i in "${!DOCKER_CIDS[@]}"; do
            [ "${DOCKER_SELECTED[$i]}" = true ] || continue
            write_field "selected_docker_container" "${DOCKER_CIDS[$i]:0:12}|${DOCKER_NAMES[$i]}|${DOCKER_SERVICES[$i]}" "docker ps/top" "cid|name|services"
        done
    fi
}
collect_u052() { begin_item "U-052" "패스워드 사용기간, 복잡도 설정 및 암호화 저장"; collect_db_common; end_item; }
collect_u053() {
    begin_item "U-053" "DB 원격 접속 제한"; collect_db_common
    for p in /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf /var/lib/pgsql/data/postgresql.conf /etc/postgresql/*/main/postgresql.conf; do
        [ -f "$p" ] && write_matching_lines "db_bind_setting" "$p" 'bind-address|listen_addresses'
    done
    end_item
}
collect_u054() { begin_item "U-054" "DBA이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"; collect_db_common; write_field "requires_authenticated_db_query" "true" "DB"; end_item; }
collect_u055() {
    begin_item "U-055" "데이터베이스 접근, 변경, 삭제 등의 감사기록 정책 설정"; collect_db_common
    for p in /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf /var/lib/pgsql/data/postgresql.conf /etc/postgresql/*/main/postgresql.conf; do [ -f "$p" ] && write_matching_lines "db_audit_setting" "$p" 'audit|log_statement|general_log'; done
    end_item
}
collect_u056() { begin_item "U-056" "데이터베이스 계정의 umask를 022 이상으로 설정하여 사용"; collect_db_common; write_field "current_umask" "$(umask)" "collector process"; end_item; }
collect_u057() {
    begin_item "U-057" "데이터베이스 주요 파일들의 접근 권한 설정"; collect_db_common
    for p in /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf /var/lib/pgsql/data/postgresql.conf /etc/postgresql/*/main/postgresql.conf; do [ -e "$p" ] && write_path_stat "db_config_file" "$p"; done
    end_item
}
collect_u058() {
    begin_item "U-058" "데이터베이스의 자원 제한 기능 설정"; collect_db_common
    for p in /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf /var/lib/pgsql/data/postgresql.conf /etc/postgresql/*/main/postgresql.conf; do [ -f "$p" ] && write_matching_lines "db_resource_setting" "$p" 'max_connections|max_user_connections|statement_timeout|connection_limit'; done
    end_item
}
collect_u059() {
    begin_item "U-059" "보안에 취약하지 않은 버전의 데이터베이스를 사용(EOS)"; collect_db_common
    write_field "mysql_version" "$(mysql --version 2>/dev/null || echo NOT_FOUND)" "mysql --version"
    write_field "postgres_version" "$(postgres --version 2>/dev/null || psql --version 2>/dev/null || echo NOT_FOUND)" "postgres/psql --version"
    write_field "mongo_version" "$(mongod --version 2>/dev/null | head -n1 || echo NOT_FOUND)" "mongod --version"
    end_item
}

# ------------------------------------------------------------------------------
# U-060 ~ U-066 WAS
# ------------------------------------------------------------------------------
collect_was_common() {
    detect_was || true
    ps -eo user=,comm=,args= 2>/dev/null | grep -E -i 'tomcat|catalina|jboss|wildfly|jeus' | grep -v grep | head -n 100 | while IFS= read -r l; do write_field "was_process" "$l" "ps"; done
}
collect_u060() { begin_item "U-060" "데몬 관리"; collect_was_common; end_item; }
collect_u061() { begin_item "U-061" "관리자 계정명 관리"; collect_was_common; write_field "requires_was_config_review" "true" "WAS"; end_item; }
collect_u062() { begin_item "U-062" "관리자 패스워드 관리"; collect_was_common; write_field "requires_was_config_review" "true" "WAS"; end_item; }
collect_u063() {
    begin_item "U-063" "패스워드 파일 관리"; collect_was_common
    for p in /etc/tomcat*/tomcat-users.xml /opt/tomcat/conf/tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml; do [ -e "$p" ] && write_path_stat "was_password_file" "$p"; done
    end_item
}
collect_u064() {
    begin_item "U-064" "디렉터리 쓰기 권한 관리"; collect_was_common
    for p in /opt/tomcat /usr/local/tomcat /opt/jboss /opt/wildfly /opt/jeus; do [ -e "$p" ] && write_path_stat "was_directory" "$p"; done
    end_item
}
collect_u065() {
    begin_item "U-065" "접근 로그 활성화"; collect_was_common
    for p in /opt/tomcat/conf/server.xml /usr/local/tomcat/conf/server.xml; do [ -f "$p" ] && write_matching_lines "access_log_setting" "$p" 'AccessLogValve'; done
    end_item
}
collect_u066() {
    begin_item "U-066" "최신 패치 적용"; collect_was_common
    write_field "tomcat_version" "$(catalina.sh version 2>/dev/null | grep -i 'Server version' | head -n1 || echo NOT_FOUND)" "catalina.sh"
    end_item
}

# ------------------------------------------------------------------------------
# U-067 ~ U-096 Open Source Vulnerabilities
# Evidence = matching lines from OSV scanner result. No GOOD/VULNERABLE decision here.
# ------------------------------------------------------------------------------
OSV_RESULT="${OSV_RESULT:-${PWD}/script/scan_results.txt}"

collect_osv_item() {
    local code="$1" name="$2" pattern="$3"
    begin_item "$code" "$name"
    write_field "osv_result_exists" "$( [ -f "$OSV_RESULT" ] && echo true || echo false )" "$OSV_RESULT"
    if [ -f "$OSV_RESULT" ]; then
        local count=0
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            count=$((count + 1))
            write_field "osv_match" "$line" "$OSV_RESULT"
        done < <(grep -E -i "$pattern" "$OSV_RESULT" 2>/dev/null || true)
        write_field "osv_match_count" "$count" "$OSV_RESULT"
    else
        write_field "osv_match_count" "NOT_SET" "$OSV_RESULT"
    fi
    end_item
}

collect_u067() { collect_osv_item "U-067" "Apache Log4j 취약점 점검" 'log4j|CVE-2021-44228|CVE-2021-45046|CVE-2021-45105'; }
collect_u068() { collect_osv_item "U-068" "Tomcat(Ghostcat) 취약점 점검" 'Ghostcat|CVE-2020-1938'; }
collect_u069() { collect_osv_item "U-069" "OpenSSL 취약점 점검" 'OpenSSL'; }
collect_u070() { collect_osv_item "U-070" "Shellshock 취약점 점검" 'Shellshock|CVE-2014-6271|CVE-2014-7169'; }
collect_u071() { collect_osv_item "U-071" "Linux CoW LPE 취약점 점검" 'CVE-2022-0847|CVE-2026-31431|CVE-2026-43284|CVE-2026-43500'; }
collect_u072() { collect_osv_item "U-072" "Polkit 권한 상승 취약점 점검" 'CVE-2021-4034|CVE-2021-3560|Polkit'; }
collect_u073() { collect_osv_item "U-073" "Spring4shell 취약점 점검" 'CVE-2022-22965|Spring4Shell'; }
collect_u074() { collect_osv_item "U-074" "Text4Shell 취약점 점검" 'CVE-2022-42889|Text4Shell'; }
collect_u075() { collect_osv_item "U-075" "Spring Framework 취약점 점검" 'CVE-2020-5397'; }
collect_u076() { collect_osv_item "U-076" "PHPUnit 취약점 점검" 'CVE-2017-9841|PHPUnit'; }
collect_u077() { collect_osv_item "U-077" "Apache Struts 원격 코드 실행 취약점 점검" 'CVE-2023-50164|CVE-2024-53677|Struts'; }
collect_u078() { collect_osv_item "U-078" "Apache ActiveMQ 원격 코드 실행 취약점 점검" 'CVE-2023-46604|ActiveMQ'; }
collect_u079() { collect_osv_item "U-079" "Apache Shiro 원격 코드 실행 취약점 점검" 'CVE-2023-34478|Shiro'; }
collect_u080() { collect_osv_item "U-080" "Jenkins 원격 코드 실행 취약점 점검" 'CVE-2024-23897|Jenkins'; }
collect_u081() { collect_osv_item "U-081" "Samba ZeroLogon 취약점 점검" 'CVE-2020-1472|ZeroLogon'; }
collect_u082() { collect_osv_item "U-082" "Node.js WebSocket DoS 취약점 점검" 'CVE-2024-37890|GHSA-3h5v-q93c-6h6q'; }
collect_u083() { collect_osv_item "U-083" "glibc 로컬 권한상승 취약점 점검" 'CVE-2023-6246|CVE-2023-6779|CVE-2023-6780'; }
collect_u084() { collect_osv_item "U-084" "OpenSSH 원격 코드 실행 취약점 점검" 'CVE-2023-38408|CVE-2024-6387'; }
collect_u085() { collect_osv_item "U-085" "Red Hat JBoss RichFaces Lib 원격 코드 실행 취약점 점검" 'CVE-2013-2165|CVE-2013-4316|CVE-2018-14667|RichFaces'; }
collect_u086() { collect_osv_item "U-086" "Kernel 권한 상승 취약점 점검" 'CVE-2024-53141'; }
collect_u087() { collect_osv_item "U-087" "glibc Looney Tunables 권한 상승 취약점 점검" 'CVE-2023-4911|Looney'; }
collect_u088() { collect_osv_item "U-088" "curl BOF 취약점 점검" 'CVE-2019-5435|CVE-2023-38545|curl'; }
collect_u089() { collect_osv_item "U-089" "Use-After-Free 커널 취약점 점검" 'CVE-2021-22555|CVE-2023-32233|CVE-2024-1086'; }
collect_u090() { collect_osv_item "U-090" "Node.js cross-spawn ReDoS 취약점 점검" 'CVE-2024-21538|cross-spawn'; }
collect_u091() { collect_osv_item "U-091" "Root 권한 획득 취약점 점검" 'CVE-2023-0386'; }
collect_u092() { collect_osv_item "U-092" "React2Shell 취약점 점검" 'CVE-2025-55182|React2Shell'; }
collect_u093() { collect_osv_item "U-093" "Apache Tomcat 원격 코드 실행 취약점 점검" 'CVE-2025-24813|CVE-2025-55752|CVE-2025-55754'; }
collect_u094() { collect_osv_item "U-094" "Apache Tika XXE 취약점 점검" 'CVE-2025-54988|CVE-2025-66516|Apache Tika'; }
collect_u095() { collect_osv_item "U-095" "sudo 모듈 권한 상승 취약점 점검" 'CVE-2025-32463|sudo'; }
collect_u096() { collect_osv_item "U-096" "Linux CoW LPE 취약점 점검" 'CVE-2016-5195|Dirty CoW'; }

# ------------------------------------------------------------------------------
# U-097 ~ U-100 Incident traces
# ------------------------------------------------------------------------------
collect_u097() {
    begin_item "U-097" "Rootkit 점검"
    local chk="${CHKROOTKIT_RESULT:-${PWD}/script/chkrootkit_result.txt}"
    write_field "rootkit_result_exists" "$( [ -f "$chk" ] && echo true || echo false )" "$chk"
    if [ -f "$chk" ]; then
        local count="$(grep -E -i -c 'INFECTED|WARNING' "$chk" 2>/dev/null || true)"
        write_field "rootkit_suspicious_count" "${count:-0}" "$chk"
        grep -E -i 'INFECTED|WARNING' "$chk" 2>/dev/null | head -n 100 | while IFS= read -r l; do write_field "rootkit_suspicious_line" "$l" "$chk"; done
    else
        write_field "rootkit_suspicious_count" "NOT_SET" "$chk"
    fi
    end_item
}
collect_u098() {
    begin_item "U-098" "BPFdoor(cBPFdoor/eBPFdoor) 및 Raw Socket 악용 여부 점검"
    local raw=""
    if command -v ss >/dev/null 2>&1; then raw="$(ss -ap 2>/dev/null | grep -i raw || true)"; fi
    while IFS= read -r l; do [ -n "$l" ] && write_field "raw_socket_line" "$l" "ss -ap"; done <<< "$raw"
    if command -v bpftool >/dev/null 2>&1; then
        bpftool prog show 2>/dev/null | head -n 200 | while IFS= read -r l; do write_field "bpf_program" "$l" "bpftool prog show"; done
    else
        write_field "bpftool_present" "false" "PATH"
    fi
    end_item
}
collect_u099() {
    begin_item "U-099" "WebShell 점검"
    local r="${WEBSHELL_RESULT:-${PWD}/script/webshell_result.txt}"
    write_field "webshell_result_exists" "$( [ -f "$r" ] && echo true || echo false )" "$r"
    if [ -f "$r" ]; then
        local count="$(grep -E -i -c 'YARA Match|webshell|suspicious|malicious' "$r" 2>/dev/null || true)"
        write_field "webshell_suspicious_count" "${count:-0}" "$r"
        grep -E -i 'YARA Match|webshell|suspicious|malicious' "$r" 2>/dev/null | head -n 200 | while IFS= read -r l; do write_field "webshell_suspicious_line" "$l" "$r"; done
    else
        write_field "webshell_suspicious_count" "NOT_SET" "$r"
    fi
    end_item
}
collect_u100() {
    begin_item "U-100" "Hosts 파일 변조"
    write_path_stat "hosts_file" /etc/hosts
    if [ -f /etc/hosts ]; then
        grep -v -E '^[[:space:]]*(#|$)' /etc/hosts 2>/dev/null | while IFS= read -r l; do write_field "hosts_entry" "$l" "/etc/hosts"; done
    fi
    end_item
}

# ==============================================================================
# Run all collectors with progress logging
# ==============================================================================

TOTAL_CHECKS=100

run_check() {
    local current="$1"
    local total="$2"
    local code="$3"
    local func="$4"
    local name="$5"
    local percent=$(( current * 100 / total ))

    printf '[진행률] %3d/%d (%3d%%) - %s %s ... ' \
        "$current" "$total" "$percent" "$code" "$name"

    if "$func"; then
        printf '완료\n'
        return 0
    else
        local rc=$?
        printf '오류(rc=%d)\n' "$rc"
        return "$rc"
    fi
}

ERROR_COUNT=0

run_check 1 "$TOTAL_CHECKS" "U-001" "collect_u001" "관리자계정 외 su 명령어 제한" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 2 "$TOTAL_CHECKS" "U-002" "collect_u002" "계정 잠금 임계값 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 3 "$TOTAL_CHECKS" "U-003" "collect_u003" "Session Timeout 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 4 "$TOTAL_CHECKS" "U-004" "collect_u004" "비밀번호 관리정책 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 5 "$TOTAL_CHECKS" "U-005" "collect_u005" "root 계정 원격접속 제한(Telnet, SSH 등 원격접속)" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 6 "$TOTAL_CHECKS" "U-006" "collect_u006" "불필요한 시스템 계정 Shell 제한 여부" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 7 "$TOTAL_CHECKS" "U-007" "collect_u007" "패스워드 암호화 저장" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 8 "$TOTAL_CHECKS" "U-008" "collect_u008" "동일한 UID 금지" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 9 "$TOTAL_CHECKS" "U-009" "collect_u009" "root 이외의 UID가 0 금지" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 10 "$TOTAL_CHECKS" "U-010" "collect_u010" "안전한 비밀번호 암호화 알고리즘 사용" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 11 "$TOTAL_CHECKS" "U-011" "collect_u011" "DoS 공격에 취약한 서비스 비활성화" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 12 "$TOTAL_CHECKS" "U-012" "collect_u012" "불필요한 서비스 비활성화" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 13 "$TOTAL_CHECKS" "U-013" "collect_u013" "취약한 서비스 비활성화" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 14 "$TOTAL_CHECKS" "U-014" "collect_u014" "Cron 관련 파일 소유자 및 권한 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 15 "$TOTAL_CHECKS" "U-015" "collect_u015" "암호화되지 않는 FTP 서비스 비활성화" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 16 "$TOTAL_CHECKS" "U-016" "collect_u016" "ftpusers 파일 소유자 및 권한 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 17 "$TOTAL_CHECKS" "U-017" "collect_u017" "ftpusers 파일 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 18 "$TOTAL_CHECKS" "U-018" "collect_u018" "공유 서비스에 대한 익명 접근 제한 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 19 "$TOTAL_CHECKS" "U-019" "collect_u019" "암호화된 원격접속 서비스 사용 및 기본 포트 변경" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 20 "$TOTAL_CHECKS" "U-020" "collect_u020" "NFS 접근통제" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 21 "$TOTAL_CHECKS" "U-021" "collect_u021" "NFS 설정파일 접근권한" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 22 "$TOTAL_CHECKS" "U-022" "collect_u022" "SMTP expn, vrfy 명령어 제한" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 23 "$TOTAL_CHECKS" "U-023" "collect_u023" "DNS Zone Transfer 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 24 "$TOTAL_CHECKS" "U-024" "collect_u024" "SNMP 서비스 Community String의 복잡성 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 25 "$TOTAL_CHECKS" "U-025" "collect_u025" "sudo 명령어 접근 관리" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 26 "$TOTAL_CHECKS" "U-026" "collect_u026" "웹 서비스 디렉터리 쓰기 권한 관리" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 27 "$TOTAL_CHECKS" "U-027" "collect_u027" "웹 서비스 소스/설정파일 권한 관리" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 28 "$TOTAL_CHECKS" "U-028" "collect_u028" "웹 서비스 파일 업로드 및 다운로드 용량 제한" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 29 "$TOTAL_CHECKS" "U-029" "collect_u029" "웹 서비스 상위 디렉터리 접근 금지" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 30 "$TOTAL_CHECKS" "U-030" "collect_u030" "웹 서비스 정보 숨김" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 31 "$TOTAL_CHECKS" "U-031" "collect_u031" "웹 서비스 링크 사용금지" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 32 "$TOTAL_CHECKS" "U-032" "collect_u032" "웹 서비스 CGI 스크립트 실행 제한" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 33 "$TOTAL_CHECKS" "U-033" "collect_u033" "웹 서비스 디렉터리 리스팅 제거" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 34 "$TOTAL_CHECKS" "U-034" "collect_u034" "웹 서비스 영역의 분리" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 35 "$TOTAL_CHECKS" "U-035" "collect_u035" "웹 서비스 불필요한 파일 제거" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 36 "$TOTAL_CHECKS" "U-036" "collect_u036" "웹 서비스 데몬 관리" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 37 "$TOTAL_CHECKS" "U-037" "collect_u037" "UMASK 설정 관리" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 38 "$TOTAL_CHECKS" "U-038" "collect_u038" "/etc/(x)inetd.conf 파일 소유자 및 권한 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 39 "$TOTAL_CHECKS" "U-039" "collect_u039" "/etc/shadow 파일 소유자 및 권한 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 40 "$TOTAL_CHECKS" "U-040" "collect_u040" "/etc/hosts 파일 소유자 및 권한 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 41 "$TOTAL_CHECKS" "U-041" "collect_u041" "/etc/syslog.conf 파일 소유자 및 권한 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 42 "$TOTAL_CHECKS" "U-042" "collect_u042" "사용자 홈디렉터리 내 환경변수 파일 소유자 및 권한 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 43 "$TOTAL_CHECKS" "U-043" "collect_u043" "root 계정 환경변수의 'PATH' 값 보안설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 44 "$TOTAL_CHECKS" "U-044" "collect_u044" "접속 IP 및 포트 제한" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 45 "$TOTAL_CHECKS" "U-045" "collect_u045" "/etc/passwd 파일 소유자 및 권한 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 46 "$TOTAL_CHECKS" "U-046" "collect_u046" "/etc/services 파일 소유자 및 권한 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 47 "$TOTAL_CHECKS" "U-047" "collect_u047" "보안에 취약하지 않은 버전의 OS를 사용" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 48 "$TOTAL_CHECKS" "U-048" "collect_u048" "서비스 최신 보안 패치 적용 여부(DNS, SMTP 등)" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 49 "$TOTAL_CHECKS" "U-049" "collect_u049" "정책에 따른 시스템 로깅 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 50 "$TOTAL_CHECKS" "U-050" "collect_u050" "로그 디렉터리 소유자 및 권한 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 51 "$TOTAL_CHECKS" "U-051" "collect_u051" "중요데이터 백업 여부" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 52 "$TOTAL_CHECKS" "U-052" "collect_u052" "패스워드 사용기간, 복잡도 설정 및 암호화 저장" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 53 "$TOTAL_CHECKS" "U-053" "collect_u053" "DB 원격 접속 제한" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 54 "$TOTAL_CHECKS" "U-054" "collect_u054" "DBA이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 55 "$TOTAL_CHECKS" "U-055" "collect_u055" "데이터베이스 접근, 변경, 삭제 등의 감사기록 정책 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 56 "$TOTAL_CHECKS" "U-056" "collect_u056" "데이터베이스 계정의 umask를 022 이상으로 설정하여 사용" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 57 "$TOTAL_CHECKS" "U-057" "collect_u057" "데이터베이스 주요 파일들의 접근 권한 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 58 "$TOTAL_CHECKS" "U-058" "collect_u058" "데이터베이스의 자원 제한 기능 설정" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 59 "$TOTAL_CHECKS" "U-059" "collect_u059" "보안에 취약하지 않은 버전의 데이터베이스를 사용(EOS)" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 60 "$TOTAL_CHECKS" "U-060" "collect_u060" "데몬 관리" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 61 "$TOTAL_CHECKS" "U-061" "collect_u061" "관리자 계정명 관리" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 62 "$TOTAL_CHECKS" "U-062" "collect_u062" "관리자 패스워드 관리" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 63 "$TOTAL_CHECKS" "U-063" "collect_u063" "패스워드 파일 관리" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 64 "$TOTAL_CHECKS" "U-064" "collect_u064" "디렉터리 쓰기 권한 관리" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 65 "$TOTAL_CHECKS" "U-065" "collect_u065" "접근 로그 활성화" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 66 "$TOTAL_CHECKS" "U-066" "collect_u066" "최신 패치 적용" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 67 "$TOTAL_CHECKS" "U-067" "collect_u067" "Apache Log4j 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 68 "$TOTAL_CHECKS" "U-068" "collect_u068" "Tomcat(Ghostcat) 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 69 "$TOTAL_CHECKS" "U-069" "collect_u069" "OpenSSL 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 70 "$TOTAL_CHECKS" "U-070" "collect_u070" "Shellshock 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 71 "$TOTAL_CHECKS" "U-071" "collect_u071" "Linux CoW LPE 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 72 "$TOTAL_CHECKS" "U-072" "collect_u072" "Polkit 권한 상승 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 73 "$TOTAL_CHECKS" "U-073" "collect_u073" "Spring4shell 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 74 "$TOTAL_CHECKS" "U-074" "collect_u074" "Text4Shell 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 75 "$TOTAL_CHECKS" "U-075" "collect_u075" "Spring Framework 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 76 "$TOTAL_CHECKS" "U-076" "collect_u076" "PHPUnit 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 77 "$TOTAL_CHECKS" "U-077" "collect_u077" "Apache Struts 원격 코드 실행 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 78 "$TOTAL_CHECKS" "U-078" "collect_u078" "Apache ActiveMQ 원격 코드 실행 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 79 "$TOTAL_CHECKS" "U-079" "collect_u079" "Apache Shiro 원격 코드 실행 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 80 "$TOTAL_CHECKS" "U-080" "collect_u080" "Jenkins 원격 코드 실행 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 81 "$TOTAL_CHECKS" "U-081" "collect_u081" "Samba ZeroLogon 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 82 "$TOTAL_CHECKS" "U-082" "collect_u082" "Node.js WebSocket DoS 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 83 "$TOTAL_CHECKS" "U-083" "collect_u083" "glibc 로컬 권한상승 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 84 "$TOTAL_CHECKS" "U-084" "collect_u084" "OpenSSH 원격 코드 실행 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 85 "$TOTAL_CHECKS" "U-085" "collect_u085" "Red Hat JBoss RichFaces Lib 원격 코드 실행 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 86 "$TOTAL_CHECKS" "U-086" "collect_u086" "Kernel 권한 상승 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 87 "$TOTAL_CHECKS" "U-087" "collect_u087" "glibc Looney Tunables 권한 상승 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 88 "$TOTAL_CHECKS" "U-088" "collect_u088" "curl BOF 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 89 "$TOTAL_CHECKS" "U-089" "collect_u089" "Use-After-Free 커널 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 90 "$TOTAL_CHECKS" "U-090" "collect_u090" "Node.js cross-spawn ReDoS 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 91 "$TOTAL_CHECKS" "U-091" "collect_u091" "Root 권한 획득 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 92 "$TOTAL_CHECKS" "U-092" "collect_u092" "React2Shell 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 93 "$TOTAL_CHECKS" "U-093" "collect_u093" "Apache Tomcat 원격 코드 실행 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 94 "$TOTAL_CHECKS" "U-094" "collect_u094" "Apache Tika XXE 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 95 "$TOTAL_CHECKS" "U-095" "collect_u095" "sudo 모듈 권한 상승 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 96 "$TOTAL_CHECKS" "U-096" "collect_u096" "Linux CoW LPE 취약점 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 97 "$TOTAL_CHECKS" "U-097" "collect_u097" "Rootkit 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 98 "$TOTAL_CHECKS" "U-098" "collect_u098" "BPFdoor(cBPFdoor/eBPFdoor) 및 Raw Socket 악용 여부 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 99 "$TOTAL_CHECKS" "U-099" "collect_u099" "WebShell 점검" || ERROR_COUNT=$((ERROR_COUNT + 1))
run_check 100 "$TOTAL_CHECKS" "U-100" "collect_u100" "Hosts 파일 변조" || ERROR_COUNT=$((ERROR_COUNT + 1))

printf '</EVIDENCE>\n' >> "$OUT_FILE"
printf '\n[INFO] Evidence collection completed: %s\n' "$OUT_FILE"
printf '[INFO] Completed checks: %d/%d\n' "$((TOTAL_CHECKS - ERROR_COUNT))" "$TOTAL_CHECKS"
if [ "$ERROR_COUNT" -gt 0 ]; then
    printf '[WARN] Collector errors: %d\n' "$ERROR_COUNT"
else
    printf '[INFO] Collector errors: 0\n'
fi
