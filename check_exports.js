// libflutter.so에 BoringSSL/X509 관련 심볼이 export 돼 있는지 확인용
// 사용법: frida -D <기기ID> -f kr.co.niceinfo.nimoandroid -l check_exports.js
// (앱 켜지고 조금 있다가 Ctrl+C로 종료해도 됨, 로그인 안 해도 됨)

Java.perform(function () {
    setTimeout(function () {
        var lib = Process.findModuleByName("libflutter.so");
        if (!lib) {
            console.log("[-] libflutter.so 아직 안 뜸, 3초 후 재시도 필요");
            return;
        }
        console.log("[*] libflutter.so exports 스캔 중...");
        var exports = lib.enumerateExports();
        console.log("[*] 총 export 개수: " + exports.length);

        var keywords = ["x509", "verify", "ssl_", "SSL_", "cert"];
        var hits = [];
        exports.forEach(function (e) {
            var nameLower = e.name.toLowerCase();
            for (var i = 0; i < keywords.length; i++) {
                if (nameLower.indexOf(keywords[i].toLowerCase()) !== -1) {
                    hits.push(e.name + "  (" + e.type + ")  " + e.address);
                    break;
                }
            }
        });

        if (hits.length === 0) {
            console.log("[-] X509/verify/ssl/cert 관련 export 없음 -> 심볼 전부 숨겨진 상태, 수동 오프셋 필요");
        } else {
            console.log("[+] 관련 export " + hits.length + "개 발견:");
            hits.forEach(function (h) { console.log("    " + h); });
        }
    }, 2000);
});
