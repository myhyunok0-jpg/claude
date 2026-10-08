# NIMO iOS IPA 덤프 가이드 (frida-ios-dump 기반)

탈옥된 아이폰에서 설치된 NIMO 앱을 복호화된 IPA로 추출하는 절차입니다.
(동일한 모의해킹 엔게이지먼트 — Android와 같은 앱 분석 목적)

---

## 1. 아이폰(탈옥 기기)에 frida-server 설치

Cydia 또는 Sileo 앱에서:

1. 소스(Source) 추가: `https://build.frida.re`
2. 검색창에 `frida` 검색 → **Frida** 패키지 설치
3. 설치 후 SSH로 확인:

```bash
# PC에서 (USB 연결 상태, usbmuxd 필요)
ssh root@localhost -p 2222   # iproxy로 포트포워딩 했을 때
# 또는 Wi-Fi: ssh root@<iPhone_IP>

frida-ps   # 기본 비밀번호는 보통 alpine (바꾸는 걸 권장)
ps -A | grep frida   # frida-server 떠있는지 확인
```

USB로 붙일 거면 `libimobiledevice`의 `iproxy`가 필요합니다:

```bash
# PC (Windows면 WSL 또는 usbmuxd용 iTunes 드라이버 필요)
iproxy 2222 22
```

---

## 2. PC에 frida-ios-dump 세팅

```bash
git clone https://github.com/AloneMonkey/frida-ios-dump.git
cd frida-ios-dump
pip3 install -r requirements.txt
```

`dump.py` 상단의 접속 정보를 본인 환경에 맞게 수정하거나, USB 연결이면 `-u` 옵션으로 자동 인식됩니다.

---

## 3. NIMO 앱의 Bundle ID 확인

```bash
frida-ps -Uai
```

출력에서 NIMO 앱 찾기 (보통 `kr.co.niceinfo.nimo` 또는 `kr.co.niceinfo.nimoios` 류 — 정확한 값은 목록에서 확인).

---

## 4. 덤프 실행

```bash
# USB 연결 기준
python3 dump.py -u "NIMO"
# 또는 bundle id로
python3 dump.py -u kr.co.niceinfo.nimo

# Wi-Fi 연결 기준 (SSH 포트/비번 다르면 옵션 추가)
python3 dump.py -H <iPhone_IP> -u "NIMO"
```

성공하면 현재 디렉토리에 `NIMO.ipa` (복호화된 상태)가 생성됩니다.

---

## 5. 덤프된 IPA 확인/분석

```bash
unzip -o NIMO.ipa -d NIMO_extracted
cd NIMO_extracted/Payload/*.app

# 암호화 해제됐는지 확인 (cryptid가 0이어야 정상 복호화된 것)
otool -l NIMO | grep -A4 LC_ENCRYPTION_INFO
```

`cryptid 0`이면 성공입니다. 이 바이너리를 Hopper/IDA/Ghidra로 열어서
루팅(jailbreak) 탐지, 인증서 피닝 로직 등을 Android 때와 같은 방식으로
분석하면 됩니다 — Mach-O라 구조는 다르지만 BoringSSL/OpenSSL 사용 패턴을
찾는 건 같은 접근법(assert 문자열 → XREF 역추적)이 통할 가능성이 높습니다.

---

## 트러블슈팅

- **"Unable to find Gadget"/"process not found"**: frida-server 버전과
  PC의 frida 파이썬 패키지 버전을 맞추세요 (`pip show frida` vs
  `frida-ps` 버전 비교).
- **SSH 접속 안 됨**: 탈옥 기기 비밀번호 기본값은 `alpine`인 경우가
  많습니다. 반드시 바꾸는 걸 권장합니다(보안).
- **"App is not encrypted" 에러**: App Store에서 받은 정식 설치본이
  아니라 사이드로드/TestFlight 등으로 깔린 경우 애초에 암호화가
  안 걸려있을 수 있습니다 — 이 경우 `unzip`만으로도 바로 분석 가능한
  바이너리가 나옵니다.
