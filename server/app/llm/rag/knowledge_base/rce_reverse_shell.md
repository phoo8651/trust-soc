# Remote Code Execution (RCE) 및 Reverse Shell 대응 가이드

## 개요
RCE(원격 코드 실행)는 공격자가 시스템 명령어를 원격에서 실행할 수 있는 가장 치명적인 취약점 중 하나입니다. 공격자는 이를 통해 **Reverse Shell**을 생성하여 서버의 제어권을 탈취하거나 악성코드를 다운로드하여 실행할 수 있습니다.

## 탐지 지표 (Indicators)
- **쉘 연결 시도**: `/bin/sh -i`, `/bin/bash -i` 등 인터랙티브 쉘 실행 시도
- **네트워크 연결**: `/dev/tcp/`, `nc -e` (Netcat), `socket` 모듈 등을 이용한 아웃바운드 연결 시도
- **파일 다운로드**: `wget`, `curl` 등을 이용해 외부 신뢰할 수 없는 소스에서 `.sh`, `.elf` 파일 다운로드 및 실행 (`| bash`)
- **시스템 정찰**: `whoami`, `id`, `uname -a`, `cat /etc/passwd` 등 정찰 명령어 실행

## 대응 절차 (Playbook)

### 1. 즉시 격리 (Containment)
- **네트워크 단절**: 피해 시스템을 네트워크에서 즉시 분리하여 내부망 확산(Lateral Movement)을 방지하십시오.
- **서비스 중단**: 웹 서버 등 취약한 서비스를 일시 중단하십시오.

### 2. 프로세스 및 연결 종료
- **프로세스 킬**: 의심스러운 쉘 프로세스(예: `nc`, `bash`가 웹 프로세스의 자식으로 실행 중인 경우)를 강제 종료(`kill -9`)하십시오.
- **세션 차단**: 공격자의 IP와 연결된 모든 네트워크 세션을 차단하십시오.

### 3. 침해 사고 조사 (Forensic)
- **파일 무결성 검사**: 웹쉘(WebShell)이 생성되었거나 시스템 파일이 변조되었는지 확인하십시오.
- **지속성 확인**: CronJob, 시작 프로그램, `.bashrc` 등에 백도어가 설치되었는지 점검하십시오.
- **취약점 패치**: 공격 경로로 이용된 애플리케이션의 취약점을 파악하고 보안 패치를 적용하십시오.

## 권장 조치 요약
- Isolate Host Immediately
- Kill Suspicious Processes
- Check for WebShells
- Patch Vulnerability