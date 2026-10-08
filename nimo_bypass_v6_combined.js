/*
 * NIMO (kr.co.niceinfo.nimoandroid) 루팅/위변조 우회 + SSL 피닝 우회 통합 v6
 *
 * 베이스: 기존 v5 루팅/위변조 우회 로직 유지
 * 추가:  1) Android Java 레벨 SSL 피닝 우회 강화
 *          - SSLContext.init 전체 overload 커버
 *          - X509TrustManager / HostnameVerifier 우회
 *          - OkHttp3 CertificatePinner.check 우회 (여러 overload)
 *          - TrustKit / Conscrypt 우회
 *          - WebView 인증서 오류 무시
 *        2) Flutter 엔진(BoringSSL) 레벨 SSL 피닝 우회
 *          - libflutter.so 내 ssl_crypto_x509_session_verify_cert_chain
 *            / ssl_verify_peer_cert 패턴 스캔 후 강제 성공 리턴
 *          - NIMO는 Flutter 앱(MethodChannel 기반)이라 Dart http/dio가
 *            Java TLS 스택을 거치지 않고 BoringSSL을 직접 쓰는 경우가
 *            많음 → 이 레이어가 실제 피닝 우회의 핵심
 *
 * 사용법:
 *   frida -D <기기ID> -f kr.co.niceinfo.nimoandroid -l nimo_bypass_v6_combined.js
 *
 * 주의:
 *   - 정식 권한이 있는 모의해킹/보안 테스트 환경에서만 사용하세요.
 *   - libflutter.so 패턴은 Flutter 엔진 빌드 버전마다 조금씩 다를 수 있어
 *     하나라도 매칭되면 성공, 전부 실패하면 콘솔 로그로 실패 사실이 보입니다.
 */

console.log("[*] NIMO 루팅/위변조 + SSL 피닝 우회 v6 시작");

// ============================================================
// Part A. Flutter/BoringSSL 네이티브 레벨 SSL 피닝 우회
//   (Java.perform 이전/이후 상관없이 독립적으로 동작)
// ============================================================
function bypassFlutterTlsPinning() {
    var libflutter = Process.findModuleByName("libflutter.so");
    if (!libflutter) {
        console.log("[F-] libflutter.so 모듈을 찾을 수 없음 (네이티브 Flutter 엔진이 아직 로드 안 됨?)");
        return false;
    }
    console.log("[F] libflutter.so 발견: base=" + libflutter.base + " size=" + libflutter.size);

    // BoringSSL 인증서 체인 검증 함수들에서 공통적으로 나타나는 바이트 패턴.
    // 실제 오프셋은 빌드마다 다르므로 Memory.scan으로 함수 시그니처를 찾는다.
    // (아래 패턴은 공개된 Flutter SSL-pinning-bypass 프로젝트들에서 널리
    //  쓰이는 ssl_crypto_x509_session_verify_cert_chain / ssl_verify_peer_cert
    //  시그니처 조각이며, 매칭되면 해당 함수의 리턴값을 강제로 1(성공)로 만든다)
    var patterns = [
        // arm64 각 Flutter 엔진 버전대에서 흔히 보이는 프롤로그 패턴 예시
        "EA 07 1E 36 69 92 1D 00",         // 패턴 후보 1
        "EA 07 1F 36 69 92 1D 00",         // 패턴 후보 2
        "FF 83 00 D1 FD 7B 01 A9 FD 03 00 91 F3 0B 00 F9", // stp/sub 프롤로그 후보
    ];

    var found = false;
    patterns.forEach(function (pattern) {
        try {
            Memory.scanSync(libflutter.base, libflutter.size, pattern).forEach(function (match) {
                found = true;
                console.log("[F+] 패턴 매칭: " + pattern + " @ " + match.address);
                try {
                    Interceptor.attach(match.address, {
                        onLeave: function (retval) {
                            // 인증서 검증 성공(보통 1 또는 0x1)으로 강제 변경
                            retval.replace(0x1);
                        }
                    });
                    console.log("[F+] " + match.address + " 후킹 완료 (강제 성공 리턴)");
                } catch (e) {
                    console.log("[F-] " + match.address + " 후킹 실패: " + e);
                }
            });
        } catch (e) {
            // 특정 패턴이 안 맞는 건 정상 (엔진 버전별 차이)
        }
    });

    if (!found) {
        console.log("[F-] 알려진 BoringSSL 검증 함수 패턴을 못 찾음.");
        console.log("[F-] -> 'frida-boringssl-scanner' 류 도구로 현재 빌드의 실제 오프셋을");
        console.log("[F-]    먼저 덤프해서 패턴을 갱신해야 할 수 있습니다.");
    }
    return found;
}

// 네이티브 모듈은 앱 실행 중 로드되므로, 로드 이벤트를 감시해서
// libflutter.so가 뜨는 즉시 후킹을 건다.
try {
    var alreadyHooked = bypassFlutterTlsPinning();
    if (!alreadyHooked) {
        Java.perform(function () {
            // SystemClassLoader 로드 시점 전후로 재시도
            setTimeout(function () {
                bypassFlutterTlsPinning();
            }, 1500);
        });
    }
} catch (e) {
    console.log("[F-] 네이티브 SSL 우회 초기화 오류: " + e);
}


Java.perform(function () {

    // ============================================================
    // Part B. 기존 v5 루팅/위변조 우회 로직 (그대로 유지)
    // ============================================================

    // [B] Java SSLContext TrustManager 우회
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TM = Java.registerClass({
            name: 'com.nimo.BypassTM6',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var TMs = [TM.$new()];

        // 모든 SSLContext.init overload 커버
        var overloads = SSLContext.init.overloads;
        overloads.forEach(function (ov) {
            ov.implementation = function (km, tm, sr) {
                console.log("[B] SSLContext.init() 가로챔 -> 커스텀 TrustManager 적용");
                return this.init(km, TMs, sr);
            };
        });
        console.log("[B+] Java SSLContext 우회 완료 (overload " + overloads.length + "개)");
    } catch (e) { console.log("[B-] Java SSL 우회 실패: " + e); }

    // [1] MethodChannel(I4.p) 호출 가로채기 — onAppironResult 결과 조작
    try {
        var P = Java.use("I4.p");
        P.a.overload('java.lang.String', 'java.lang.Object', 'I4.p$a').implementation = function (method, args, callback) {
            if (method === "onAppironResult") {
                console.log("[!] onAppironResult 가로챔 — 결과 강제 정상화");
                var HashMap = Java.use("java.util.HashMap");
                var Boolean_ = Java.use("java.lang.Boolean");
                var fakeMap = HashMap.$new();
                fakeMap.put("isCorrupted", Boolean_.valueOf(false));
                fakeMap.put("isRooted", Boolean_.valueOf(false));
                fakeMap.put("isDebug", Boolean_.valueOf(false));
                return this.a(method, Java.cast(fakeMap, Java.use("java.lang.Object")), callback);
            }
            return this.a(method, args, callback);
        };
        console.log("[1+] MethodChannel(I4.p.a) 후킹 완료");
    } catch (e) {
        console.log("[1-] I4.p.a 후킹 실패, 대체 방식 시도: " + e);
        try {
            var MainActivity = Java.use("kr.co.niceinfo.nimo_app.MainActivity");
            var HashMap2 = Java.use("java.util.HashMap");
            var Boolean2 = Java.use("java.lang.Boolean");
            MainActivity.onResult.implementation = function (bArr) {
                console.log("[!] AppIron onResult() -> 정상화 (대체 방식)");
                try {
                    var map = HashMap2.$new();
                    map.put("isCorrupted", Boolean2.valueOf(false));
                    map.put("isRooted", Boolean2.valueOf(false));
                    map.put("isDebug", Boolean2.valueOf(false));
                    var pVar = null;
                    try { pVar = MainActivity.J.value; } catch(e1) {}
                    if (!pVar) try { pVar = MainActivity.f11965J.value; } catch(e2) {}
                    if (!pVar) try { pVar = MainActivity.G.value; } catch(e3) {}
                    if (!pVar) try { pVar = MainActivity.f11964G.value; } catch(e4) {}
                    if (pVar) {
                        pVar.a("onAppironResult", map, null);
                        console.log("[+] Flutter에 정상 결과 전달 완료");
                    } else {
                        console.log("[-] MethodChannel 필드를 찾을 수 없음");
                    }
                } catch (e) { console.log("[-] onResult 대체 오류: " + e); }
            };
            console.log("[1+] onResult 대체 후킹 완료");
        } catch (e2) { console.log("[1-] 대체도 실패: " + e2); }
    }

    // [2] AppIron onError — 무시
    try {
        Java.use("kr.co.niceinfo.nimo_app.MainActivity").onError.implementation = function (err) {
            console.log("[!] AppIron onError 무시");
        };
        console.log("[2+] onError 후킹 완료");
    } catch (e) {}

    // [3] AppIronManager.start 차단 안 함
    console.log("[3] AppIronManager.start 차단 안 함");

    // [4] mVaccine BackgroundScanActivity 실행 차단
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.startActivityForResult.overload('android.content.Intent', 'int').implementation = function (intent, req) {
            try {
                var cn = intent.getComponent();
                var cls = cn ? cn.getClassName() : "";
                if (cls.indexOf("BackgroundScanActivity") !== -1 || req === 777) {
                    console.log("[!] BackgroundScanActivity 차단");
                    return;
                }
            } catch (e) {}
            return this.startActivityForResult(intent, req);
        };
        console.log("[4+] BackgroundScanActivity 차단 완료");
    } catch (e) { console.log("[4-] 실패: " + e); }

    // [5] 종료 차단
    try {
        Java.use("java.lang.System").exit.implementation = function (c) { console.log("[!] System.exit(" + c + ") 차단"); };
        Java.use("android.os.Process").killProcess.implementation = function (p) { console.log("[!] killProcess 차단"); };
        Java.use("java.lang.Runtime").exit.implementation = function (c) { console.log("[!] Runtime.exit 차단"); };
        console.log("[5+] 종료 차단 완료");
    } catch (e) {}

    // [6] File.exists 루팅경로 우회
    try {
        var File_ = Java.use("java.io.File");
        var suPaths = ["/system/bin/su","/system/xbin/su","/sbin/su","/system/app/Superuser.apk",
                       "/data/local/su","/su/bin/su","magisk","Magisk","/system/bin/magisk"];
        File_.exists.implementation = function () {
            try {
                var path = this.getAbsolutePath();
                for (var i = 0; i < suPaths.length; i++)
                    if (path.indexOf(suPaths[i]) !== -1) return false;
            } catch (e) {}
            return this.exists();
        };
        console.log("[6+] File.exists 우회 완료");
    } catch (e) {}

    // ============================================================
    // Part C. SSL 피닝 우회 강화 (OkHttp / HostnameVerifier / WebView)
    // ============================================================

    // [C1] HostnameVerifier 전체 통과
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var SSLSocket = Java.use('javax.net.ssl.SSLSession');
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
            console.log("[C1] setDefaultHostnameVerifier 호출 무시");
        };
        HttpsURLConnection.setHostnameVerifier.implementation = function (verifier) {
            console.log("[C1] setHostnameVerifier 호출 무시");
        };
        console.log("[C1+] HostnameVerifier 우회 완료");
    } catch (e) { console.log("[C1-] 실패: " + e); }

    // [C2] OkHttp3 CertificatePinner.check 우회 (여러 overload)
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        var overloadsCP = CertificatePinner.check.overloads;
        overloadsCP.forEach(function (ov) {
            ov.implementation = function () {
                console.log("[C2] OkHttp3 CertificatePinner.check() 우회");
                return;
            };
        });
        console.log("[C2+] OkHttp3 CertificatePinner 우회 완료 (" + overloadsCP.length + "개 overload)");
    } catch (e) { console.log("[C2-] OkHttp3 CertificatePinner 없음/실패: " + e); }

    try {
        var CertificatePinner2 = Java.use('okhttp3.CertificatePinner');
        CertificatePinner2['check$okhttp'] && (CertificatePinner2['check$okhttp'].implementation = function () {
            console.log("[C2] OkHttp3 check$okhttp() 우회");
            return;
        });
    } catch (e) {}

    // [C3] WebView 인증서 오류 무시 (앱 내 웹뷰 사용 시)
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            console.log("[C3] WebView SSL 오류 무시 -> proceed()");
            handler.proceed();
        };
        console.log("[C3+] WebViewClient SSL 오류 무시 완료");
    } catch (e) { console.log("[C3-] 실패: " + e); }

    // [C4] Conscrypt / TrustManagerImpl 검증 우회 (Android 7+ 강화 대응)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[C4] TrustManagerImpl.verifyChain() 우회 (host=" + host + ")");
            return untrustedChain;
        };
        console.log("[C4+] Conscrypt TrustManagerImpl 우회 완료");
    } catch (e) { console.log("[C4-] Conscrypt TrustManagerImpl 없음/실패: " + e); }

    console.log("[*] NIMO 루팅/위변조 + SSL 피닝 우회 v6 로드 완료");
});
