/*
 * 디버깅용: 루팅/위변조 우회(Part B)만 남기고 SSL 관련 후킹은 전부 제거.
 * v10에서 SSL 관련 후킹(build_chain, exit/_exit/abort, Java SSL 후킹들)이
 * 터치 무반응/시스템 ANR의 원인인지 격리하기 위한 테스트용 스크립트.
 *
 * 이걸로 테스트했을 때:
 *   - 멀쩡하면 -> SSL 관련 후킹(Part A/N/C1~C4) 중 하나가 범인
 *   - 이것도 버벅이면 -> 루팅 우회 로직 자체(Java.perform 레벨) 문제이거나
 *     Frida/기기 궁합 문제
 *
 * 사용법:
 *   frida -D <기기ID> -f kr.co.niceinfo.nimoandroid -l root_bypass_only_test.js
 */

console.log("[*] 루팅우회 ONLY 테스트 시작 (SSL 관련 후킹 전부 제외)");

Java.perform(function () {

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

    console.log("[*] 루팅우회 ONLY 로드 완료 (SSL 관련 후킹 없음)");
});
