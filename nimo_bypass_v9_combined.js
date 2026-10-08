/*
 * NIMO (kr.co.niceinfo.nimoandroid) 루팅/위변조 우회 + SSL 피닝 우회 통합 v9
 *
 * v8 -> v9 변경점:
 *  - raise()/kill() 네이티브 후킹 제거. v8 실행 중 "raise(SIGSTOP=0x13) 호출
 *    감지" 직후 frida-agent 자체가 다른 프로세스(삼성 연락처 앱) 내부에서
 *    크래시(백트레이스가 전부 frida-agent-64.so)하는 현상 확인.
 *    raise(SIGSTOP)은 Frida 자신이 spawn 직후 프로세스를 멈춰놓고 붙는
 *    내부 메커니즘에 쓰이는 것으로 추정 -> 여기에 JS 콜백을 끼워넣는 게
 *    Frida 내부 상태를 꼬이게 한 것으로 보임. exit/_exit/abort만 남김
 *    (이쪽이 "의도적 종료" 시그널에 더 가깝고 Frida 내부 메커니즘과 덜 겹침).
 *
 * v7 -> v8 변경점 (핵심):
 *  - Part A를 추측 바이트 패턴 스캔 방식에서 "실제 바이너리 정적 분석으로
 *    찾은 정확한 함수 오프셋" 방식으로 전면 교체.
 *
 *    분석 방법 (재현 가능):
 *      1) libflutter.so에 BoringSSL assert가 남긴 소스 경로 문자열
 *         ("ssl/ssl_x509.cc", "ssl/handshake.cc", "crypto/x509/x509_vfy.cc")
 *         의 정확한 주소를 바이너리에서 직접 탐색
 *      2) capstone으로 .text 전체를 디스어셈블해서 ADRP+ADD로 그 문자열
 *         주소를 참조하는 코드(어설션 지점)를 역추적
 *      3) 그 어설션을 감싸는 함수 -> 그 함수를 호출하는 함수 순으로
 *         콜그래프를 거슬러 올라가서 build_chain() (x509_vfy.cc) 특정
 *      4) build_chain()은 0x740798 / 0x74090c 두 곳에서 직접 호출되고,
 *         두 호출부 모두 "리턴값 > 0 이면 성공, <= 0 이면 실패"로 분기
 *         -> 이게 바로 X.509 체인 신뢰 검증이 실패/성공을 가르는 지점
 *
 *    오프셋 (이 APK에 들어있는 정확히 이 libflutter.so 바이너리 기준,
 *            BuildID fc84702ceb4ef3082433a3a76c506f6532c31c3b):
 *      0x724a74  build_chain()  — 코어 X.509 체인 검증 함수
 *
 *  - Interceptor.replace로 통째로 바꾸지 않고 attach+onLeave에서 "실패시에만
 *    강제 성공"으로 바꿔치기 -> build_chain 내부에서 채워지는 체인 구조체는
 *    정상적으로 유지되어, 통째로 스킵할 때 생기는 크래시 위험을 피함
 *
 * 사용법:
 *   frida -D <기기ID> -f kr.co.niceinfo.nimoandroid -l nimo_bypass_v9_combined.js
 *
 * 주의: 정식 권한이 있는 모의해킹/보안 테스트 환경에서만 사용하세요.
 *       다른 버전의 libflutter.so(다른 Flutter 엔진 빌드)에서는 오프셋이
 *       달라지므로 그대로 쓰면 안 됩니다 — 그 경우 이 파일 상단 분석
 *       방법을 다시 거쳐서 오프셋을 새로 구해야 합니다.
 */

console.log("[*] NIMO 루팅/위변조 + SSL 피닝 우회 v9 시작");

// ============================================================
// Part N. 네이티브 레벨 프로세스 종료 방어 (libc exit/_exit/abort)
//   raise()/kill()은 Frida 자신의 spawn-gating(SIGSTOP)과 충돌 위험이
//   있어 v9에서 제외함.
// ============================================================
function resolveExport(name) {
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
    var targets = ["exit", "_exit", "abort"];
    targets.forEach(function (name) {
        try {
            var addr = resolveExport(name);
            if (!addr) {
                console.log("[N-] " + name + " export 못 찾음");
                return;
            }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    console.log("[N] 네이티브 " + name + "() 호출 감지! arg0=" + args[0]);
                    try {
                        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join("\n    "));
                    } catch (e) {}
                }
            });
            console.log("[N+] " + name + " 후킹 완료 (addr=" + addr + ")");
        } catch (e) {
            console.log("[N-] " + name + " 후킹 실패: " + e);
        }
    });
})();

(function hookStrstr() {
    try {
        var strstrPtr = resolveExport("strstr");
        if (!strstrPtr) {
            console.log("[N2-] strstr export 못 찾음");
            return;
        }
        var needles = ["frida", "xposed", "gum-js-loop", "gmain", "gdbus", "pool-frida", "27042"];
        Interceptor.attach(strstrPtr, {
            onEnter: function (args) { this.haystackPtr = args[0]; },
            onLeave: function (retval) {
                if (retval.isNull()) return;
                try {
                    var haystack = this.haystackPtr.readCString();
                    if (!haystack) return;
                    for (var i = 0; i < needles.length; i++) {
                        if (haystack.indexOf(needles[i]) !== -1) {
                            console.log("[N2] strstr(\"" + needles[i] + "\") 탐지 시도 무력화");
                            retval.replace(ptr(0));
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
// Part A. Flutter/BoringSSL 네이티브 SSL 피닝 우회
//   정적 분석으로 확정한 정확한 오프셋 사용 (build_chain @ 0x724a74)
// ============================================================
var BUILD_CHAIN_OFFSET = 0x724a74;

function hookBuildChain() {
    var lib = Process.findModuleByName("libflutter.so");
    if (!lib) {
        console.log("[A-] libflutter.so 아직 안 뜸");
        return false;
    }
    try {
        var addr = lib.base.add(BUILD_CHAIN_OFFSET);
        Interceptor.attach(addr, {
            onLeave: function (retval) {
                var rv = retval.toInt32();
                if (rv <= 0) {
                    console.log("[A] build_chain() 실패(ret=" + rv + ") 감지 -> 강제 성공(1)으로 변경");
                    retval.replace(1);
                }
            }
        });
        console.log("[A+] build_chain() 후킹 완료 @ " + addr + " (base=" + lib.base + " + 0x" + BUILD_CHAIN_OFFSET.toString(16) + ")");
        return true;
    } catch (e) {
        console.log("[A-] build_chain() 후킹 실패: " + e);
        return false;
    }
}

(function initBuildChainHook() {
    if (hookBuildChain()) return;
    var retries = 0;
    var timer = setInterval(function () {
        retries++;
        if (hookBuildChain() || retries >= 10) clearInterval(timer);
    }, 1000);
})();


Java.perform(function () {

    // ============================================================
    // Part B. 기존 루팅/위변조 우회 로직
    // ============================================================
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TM = Java.registerClass({
            name: 'com.nimo.BypassTM9',
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

    try {
        Java.use("kr.co.niceinfo.nimo_app.MainActivity").onError.implementation = function (err) {
            console.log("[!] AppIron onError 무시");
        };
        console.log("[2+] onError 후킹 완료");
    } catch (e) {}

    console.log("[3] AppIronManager.start 차단 안 함");

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

    try {
        Java.use("java.lang.System").exit.implementation = function (c) { console.log("[!] System.exit(" + c + ") 차단"); };
        Java.use("android.os.Process").killProcess.implementation = function (p) { console.log("[!] killProcess 차단"); };
        Java.use("java.lang.Runtime").exit.implementation = function (c) { console.log("[!] Runtime.exit 차단"); };
        console.log("[5+] 종료 차단 완료");
    } catch (e) {}

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
    // Part C. Java 레벨 SSL 피닝 우회 (OkHttp 등 다른 경로 대비)
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
    } catch (e) { console.log("[C2-] OkHttp3 CertificatePinner 없음 (예상대로, Flutter 네이티브 경로가 핵심)"); }

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

    console.log("[*] NIMO 루팅/위변조 + SSL 피닝 우회 v8 로드 완료");
});
