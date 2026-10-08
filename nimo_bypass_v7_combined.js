/*
 * NIMO (kr.co.niceinfo.nimoandroid) 루팅/위변조 우회 + SSL 피닝 우회 통합 v7
 *
 * v6 -> v7 변경점:
 *  - [F] libflutter.so 패턴을 추측값에서 공개 검증된 arm64 패턴
 *        (NVISO disable-flutter-tls-verification 프로젝트 기준)으로 교체
 *  - [1] I4.p.a 콜백 실제 타입이 'I4.p$a'가 아니라 'I4.o'인 것을 로그로 확인,
 *        정확한 overload 시그니처로 수정
 *  - [N] 네이티브 레벨 프로세스 종료(exit/_exit/abort/raise/kill) 후킹 추가
 *        -> v6에서 "Process terminated"가 발생한 원인으로 추정되는
 *           Java 레벨에서 못 잡는 네이티브 self-kill 대응
 *  - [N2] strstr() 후킹으로 "frida"/"xposed"/"gum-js-loop" 등 문자열 탐지 무력화
 *  - [FIX] Frida 17.x에서 Module.findExportByName(null, name) API가 제거됨
 *          ("TypeError: not a function") -> resolveExport() 헬퍼로 교체
 *          (Module.findGlobalExportByName / getGlobalExportByName / libc.so
 *           모듈 직접 조회 순으로 폴백)
 *
 * 참고 출처(패턴/기법 출처, 검증은 각자 재확인):
 *  - https://github.com/NVISOsecurity/disable-flutter-tls-verification
 *  - https://codeshare.frida.re/@enovella/anti-frida-bypass/
 *
 * 사용법:
 *   frida -D <기기ID> -f kr.co.niceinfo.nimoandroid -l nimo_bypass_v7_combined.js
 *
 * 주의: 정식 권한이 있는 모의해킹/보안 테스트 환경에서만 사용하세요.
 */

console.log("[*] NIMO 루팅/위변조 + SSL 피닝 우회 v7 시작");

// ============================================================
// Part N. 네이티브 레벨 프로세스 종료 방어 (libc exit/_exit/abort/raise/kill)
//   Java.perform 이전에 최대한 빨리 걸어야 anti-tamper native ctor보다 먼저 탄다.
// ============================================================
function resolveExport(name) {
    // Frida 17.x: Module.findExportByName(null, ...)가 더 이상 함수가 아님.
    // Module.getGlobalExportByName / Module.findGlobalExportByName 로 교체,
    // 둘 다 없으면 libc.so 모듈에서 직접 찾는다 (구버전 호환 겸용).
    try {
        if (typeof Module.findGlobalExportByName === "function") {
            return Module.findGlobalExportByName(name);
        }
    } catch (e) {}
    try {
        if (typeof Module.getGlobalExportByName === "function") {
            return Module.getGlobalExportByName(name);
        }
    } catch (e) {}
    var libcCandidates = ["libc.so", "libc.so.6"];
    for (var i = 0; i < libcCandidates.length; i++) {
        try {
            var m = Process.getModuleByName(libcCandidates[i]);
            if (m) {
                var a = m.findExportByName(name);
                if (a) return a;
            }
        } catch (e) {}
    }
    return null;
}

(function hookNativeTermination() {
    var targets = ["exit", "_exit", "abort", "raise", "kill"];
    targets.forEach(function (name) {
        try {
            var addr = resolveExport(name);
            if (!addr) {
                console.log("[N-] " + name + " export 못 찾음");
                return;
            }
            // Interceptor.replace 대신 attach + onEnter에서 호출 자체를 무력화.
            // exit류 noreturn 함수를 replace로 통째로 바꾸면 스택/레지스터 상태가
            // 깨져서 오히려 바로 크래시나는 경우가 있어 onEnter에서 로그만 찍고
            // 원래 함수가 호출되지 않도록 복귀 주소로 강제 이동시키는 방식 대신,
            // 우선은 "호출 발생"을 로그로 잡아서 콜스택을 확인하는 데 집중한다.
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    console.log("[N] 네이티브 " + name + "() 호출 감지! arg0=" + args[0] +
                        "  (콜스택 아래 참고)");
                    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n    "));
                }
            });
            console.log("[N+] " + name + " 후킹 완료 (addr=" + addr + ")");
        } catch (e) {
            console.log("[N-] " + name + " 후킹 실패: " + e);
        }
    });
})();

// ============================================================
// Part N2. strstr() 후킹 — /proc/self/maps, /proc/self/status 등에서
//   "frida" / "xposed" / "gum-js-loop" / "gmain" 문자열 탐지를 무력화
// ============================================================
(function hookStrstr() {
    try {
        var strstrPtr = resolveExport("strstr");
        if (!strstrPtr) {
            console.log("[N2-] strstr export 못 찾음");
            return;
        }
        var needles = ["frida", "xposed", "gum-js-loop", "gmain", "gdbus", "pool-frida", "27042"];
        Interceptor.attach(strstrPtr, {
            onEnter: function (args) {
                this.haystackPtr = args[0];
            },
            onLeave: function (retval) {
                if (retval.isNull()) return;
                try {
                    var haystack = this.haystackPtr.readCString();
                    if (!haystack) return;
                    for (var i = 0; i < needles.length; i++) {
                        if (haystack.indexOf(needles[i]) !== -1) {
                            console.log("[N2] strstr(\"" + needles[i] + "\") 탐지 시도 무력화");
                            retval.replace(ptr(0)); // NULL -> 못 찾은 것처럼 위장
                            return;
                        }
                    }
                } catch (e) {}
            }
        });
        console.log("[N2+] strstr 후킹 완료");
    } catch (e) {
        console.log("[N2-] strstr 후킹 실패: " + e);
    }
})();

// ============================================================
// Part A. Flutter/BoringSSL 네이티브 레벨 SSL 피닝 우회
//   (NVISO disable-flutter-tls-verification 프로젝트의 공개 arm64 패턴 사용)
// ============================================================
function bypassFlutterTlsPinning() {
    var libflutter = Process.findModuleByName("libflutter.so");
    if (!libflutter) {
        console.log("[F-] libflutter.so 모듈을 찾을 수 없음 (아직 로드 안 됨?)");
        return false;
    }
    console.log("[F] libflutter.so 발견: base=" + libflutter.base + " size=" + libflutter.size);

    // arm64 전용 (대부분의 실기기 테스트 대상). x86_64 에뮬레이터면 별도 패턴 필요.
    // retval: 0 = ssl_verify_peer_cert 성공(ssl_verify_result_t OK),
    //         1 = ssl_crypto_x509_session_verify_cert_chain 성공(bool true)
    var patterns = [
        { pat: "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9", retval: 0 },
        { pat: "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9", retval: 0 },
        { pat: "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9", retval: 0 },
        { pat: "FF ?3 01 D1 F? ?? 01 A9 ?? ?? ?? 94 ?? ?? ?? 52 48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9", retval: 1 }
    ];

    var found = false;
    patterns.forEach(function (p) {
        try {
            Memory.scanSync(libflutter.base, libflutter.size, p.pat).forEach(function (match) {
                found = true;
                console.log("[F+] 패턴 매칭 (retval=" + p.retval + "): " + match.address);
                try {
                    Interceptor.replace(match.address,
                        new NativeCallback(function () { return p.retval; }, 'int', []));
                    console.log("[F+] " + match.address + " 후킹 완료 (강제 retval=" + p.retval + ")");
                } catch (e) {
                    console.log("[F-] " + match.address + " 후킹 실패: " + e);
                }
            });
        } catch (e) { /* 패턴 불일치는 정상 (엔진 버전차) */ }
    });

    if (!found) {
        console.log("[F-] 공개된 arm64 패턴 전부 불일치.");
        console.log("[F-] -> 디바이스 아키텍처가 arm64가 맞는지(getprop ro.product.cpu.abi),");
        console.log("[F-]    Flutter 엔진 버전이 패턴 발행 시점보다 훨씨 최신/구버전인지 확인 필요.");
        console.log("[F-] -> 그래도 안 되면 Ghidra로 libflutter.so에서 \"ssl_client\"/\"ssl_server\"");
        console.log("[F-]    문자열 참조를 따라가서 직접 오프셋을 찾아야 함.");
    }
    return found;
}

try {
    var alreadyHooked = bypassFlutterTlsPinning();
    if (!alreadyHooked) {
        var retries = 0;
        var retryTimer = setInterval(function () {
            retries++;
            if (bypassFlutterTlsPinning() || retries >= 8) {
                clearInterval(retryTimer);
            }
        }, 1000);
    }
} catch (e) {
    console.log("[F-] 네이티브 SSL 우회 초기화 오류: " + e);
}


Java.perform(function () {

    // ============================================================
    // Part B. 기존 루팅/위변조 우회 로직
    // ============================================================

    // [B] Java SSLContext TrustManager 우회
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TM = Java.registerClass({
            name: 'com.nimo.BypassTM7',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var TMs = [TM.$new()];
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
    //     실제 콜백 타입은 로그로 확인된 'I4.o' (이전 버전의 'I4.p$a'는 오류였음)
    try {
        var P = Java.use("I4.p");
        P.a.overload('java.lang.String', 'java.lang.Object', 'I4.o').implementation = function (method, args, callback) {
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
        console.log("[1+] MethodChannel(I4.p.a) 후킹 완료 (I4.o 시그니처)");
    } catch (e) {
        console.log("[1-] I4.p.a(I4.o) 후킹 실패, 대체 방식 시도: " + e);
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

    // [5] Java 레벨 종료 차단 (네이티브 레벨은 Part N에서 별도 로그만 수집)
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
    // Part C. SSL 피닝 우회 강화 (Java 레벨)
    // ============================================================
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
            console.log("[C1] setDefaultHostnameVerifier 호출 무시");
        };
        HttpsURLConnection.setHostnameVerifier.implementation = function (verifier) {
            console.log("[C1] setHostnameVerifier 호출 무시");
        };
        console.log("[C1+] HostnameVerifier 우회 완료");
    } catch (e) { console.log("[C1-] 실패: " + e); }

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
    } catch (e) { console.log("[C2-] OkHttp3 CertificatePinner 없음/실패 (이 앱은 OkHttp 미사용 가능성 — Flutter 네이티브 경로가 핵심): " + e); }

    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            console.log("[C3] WebView SSL 오류 무시 -> proceed()");
            handler.proceed();
        };
        console.log("[C3+] WebViewClient SSL 오류 무시 완료");
    } catch (e) { console.log("[C3-] 실패: " + e); }

    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[C4] TrustManagerImpl.verifyChain() 우회 (host=" + host + ")");
            return untrustedChain;
        };
        console.log("[C4+] Conscrypt TrustManagerImpl 우회 완료");
    } catch (e) { console.log("[C4-] Conscrypt TrustManagerImpl 없음/실패: " + e); }

    console.log("[*] NIMO 루팅/위변조 + SSL 피닝 우회 v7 로드 완료");
});
