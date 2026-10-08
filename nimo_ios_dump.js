/*
 * nimo_ios_dump.js — 순수 C API만 사용 (system() 없음, ObjC 없음)
 *
 * kr.co.niceinfo.nimoios 용으로 맞춘 버전 (com.nice.olimi용 dump_ipa_v6.js 기반)
 *
 * ObjC 메서드 호출(인자 전달 시)이 안티탬퍼링에 걸려 크래시하는 패턴을 피하기 위해
 * opendir/readdir/fopen/fwrite/mkdir 등 순수 C 라이브러리 함수만으로
 * 재귀적 디렉토리 복사를 직접 구현. objc_msgSend를 전혀 거치지 않음.
 *
 * 사용법:
 *   frida -U -f kr.co.niceinfo.nimoios -l nimo_ios_dump.js
 *
 * 결과: /var/mobile/Documents/_ipa_build/Payload/ 폴더 생성됨
 *       -> Filza로 압축(zip) 후 PC로 export, 확장자 .ipa 로 변경
 */

console.log("========================================");
console.log("[*] nimo_ios_dump 시작 (순수 C API 버전)");
console.log("========================================");

// 네이티브 레벨 크래시(access-violation, breakpoint 등)로부터 프로세스 보호.
// 문제되는 명령어를 건너뛰고 실행을 계속 시도 (완벽하진 않으나 전체 종료보다는 나음)
var _crashCount = 0;
Process.setExceptionHandler(function (details) {
    _crashCount++;
    console.log('[!!!] 네이티브 예외 감지 #' + _crashCount + ': ' + details.type + ' @ ' + details.address);
    try {
        details.context.pc = details.context.pc.add(4);
    } catch (e) {}
    return true; // 계속 실행 시도
});
console.log('[*] 네이티브 예외 핸들러 설치 완료 (안전망)');

// pthread_kill/raise/kill을 통한 SIGABRT 자가종료 무력화 (NICE 계열 앱들에서 검증된 패턴)
function makePthreadKillReplacement(addr, argTypes) {
    var orig = new NativeFunction(addr, 'int', argTypes);
    return new NativeCallback(function (a, b) {
        var sig = argTypes.length === 1 ? a : b;
        if (sig === 6 || sig === 9 || sig === 4) {
            console.log('[+] 위험 시그널(' + sig + ') 차단');
            return 0;
        }
        return argTypes.length === 1 ? orig(a) : orig(a, b);
    }, 'int', argTypes);
}

[
    { name: 'pthread_kill', types: ['pointer', 'int'] },
    { name: '__pthread_kill', types: ['int', 'int'] },
    { name: 'kill', types: ['int', 'int'] }
].forEach(function (entry) {
    var addr = Module.findGlobalExportByName(entry.name);
    if (addr) {
        Interceptor.replace(addr, makePthreadKillReplacement(addr, entry.types));
        console.log('[*] ' + entry.name + ' 무력화 완료');
    }
});
var raiseAddr = Module.findGlobalExportByName('raise');
if (raiseAddr) {
    Interceptor.replace(raiseAddr, makePthreadKillReplacement(raiseAddr, ['int']));
    console.log('[*] raise 무력화 완료');
}
console.log('[*] pthread_kill/kill/raise 무력화 설치 완료');

// ptrace(PT_DENY_ATTACH) 도 같이 무력화
var ptracePtr = Module.findGlobalExportByName('ptrace');
if (ptracePtr) {
    Interceptor.attach(ptracePtr, {
        onEnter: function (args) {
            var request = args[0].toInt32();
            this.isDenyAttach = (request === 31);
            if (this.isDenyAttach) args[0] = ptr(0);
        },
        onLeave: function (retval) {
            if (this.isDenyAttach) retval.replace(0);
        }
    });
    console.log('[*] ptrace(PT_DENY_ATTACH) 무력화 설치 완료');
}

var WORK_DIR = "/var/mobile/Documents/_ipa_build";

function nf(name, ret, args) {
    var p = Module.findGlobalExportByName(name);
    return p ? new NativeFunction(p, ret, args) : null;
}

var _mkdir = nf('mkdir', 'int', ['pointer', 'int']);
var _opendir = nf('opendir', 'pointer', ['pointer']);
var _readdir = nf('readdir', 'pointer', ['pointer']);
var _closedir = nf('closedir', 'int', ['pointer']);
var _stat = nf('stat', 'int', ['pointer', 'pointer']);
var _lstat = nf('lstat', 'int', ['pointer', 'pointer']);
var _unlink = nf('unlink', 'int', ['pointer']);
var _rmdir = nf('rmdir', 'int', ['pointer']);

var fopen = nf('fopen', 'pointer', ['pointer', 'pointer']);
var fread = nf('fread', 'uint', ['pointer', 'uint', 'uint', 'pointer']);
var fwrite = nf('fwrite', 'uint', ['pointer', 'uint', 'uint', 'pointer']);
var fclose = nf('fclose', 'int', ['pointer']);
var fseek = nf('fseek', 'int', ['pointer', 'long', 'int']);
var ftell = nf('ftell', 'long', ['pointer']);

function mkdirp(path) {
    var parts = path.split('/').filter(function (p) { return p.length > 0; });
    var current = '';
    for (var i = 0; i < parts.length; i++) {
        current += '/' + parts[i];
        _mkdir(Memory.allocUtf8String(current), 493); // 0755
    }
}

// struct dirent (Darwin):
//   d_ino (8), d_seekoff(8), d_reclen(2), d_namlen(2), d_type(1), d_name[1024]
// 오프셋: d_type = 8+8+2+2 = 20, d_name = 21
var DIRENT_D_TYPE_OFFSET = 20;
var DIRENT_D_NAME_OFFSET = 21;
var DT_DIR = 4;
var DT_REG = 8;
var DT_LNK = 10;

function copyFile(src, dst) {
    var fp = fopen(Memory.allocUtf8String(src), Memory.allocUtf8String('rb'));
    if (fp.isNull()) return false;
    fseek(fp, 0, 2);
    var sz = ftell(fp).toNumber();
    fseek(fp, 0, 0);

    var ofp = fopen(Memory.allocUtf8String(dst), Memory.allocUtf8String('wb'));
    if (ofp.isNull()) { fclose(fp); return false; }

    var CHUNK = 1024 * 1024; // 1MB 씩 복사 (큰 파일 대응)
    var remaining = sz;
    var buf = Memory.alloc(Math.min(CHUNK, sz > 0 ? sz : 1));
    while (remaining > 0) {
        var toRead = Math.min(CHUNK, remaining);
        var got = fread(buf, 1, toRead, fp);
        if (got === 0) break;
        fwrite(buf, 1, got, ofp);
        remaining -= got;
    }
    fclose(fp);
    fclose(ofp);
    return true;
}

function copyRecursiveWithOverride(src, dst, overrideFiles) {
    // overrideFiles: { "파일명": "복호화된원본경로" } - 있으면 그 파일로 교체
    _mkdir(Memory.allocUtf8String(dst), 493);

    var dirp = _opendir(Memory.allocUtf8String(src));
    if (dirp.isNull()) {
        console.log('[-] opendir 실패: ' + src);
        return 0;
    }

    var count = 0;
    while (true) {
        var entry = _readdir(dirp);
        if (entry.isNull()) break;

        var dtype = entry.add(DIRENT_D_TYPE_OFFSET).readU8();
        var name = entry.add(DIRENT_D_NAME_OFFSET).readCString();

        if (name === '.' || name === '..') continue;

        var srcPath = src + '/' + name;
        var dstPath = dst + '/' + name;

        if (dtype === DT_DIR) {
            count += copyRecursiveWithOverride(srcPath, dstPath, overrideFiles);
        } else {
            var actualSrc = srcPath;
            if (overrideFiles && overrideFiles[name]) {
                actualSrc = overrideFiles[name];
                console.log('[*] ' + name + ': 복호화본으로 교체하여 복사');
            }
            if (copyFile(actualSrc, dstPath)) {
                count++;
            } else {
                console.log('[-] 파일 복사 실패: ' + srcPath);
            }
        }
    }
    if (_closedir) _closedir(dirp);
    return count;
}

function dumpModule(mod) {
    // 암호화 구간이 아직 메모리에 안 올라와서 access violation 나는 경우 대비, 최대 3회 재시도
    for (var attempt = 1; attempt <= 3; attempt++) {
        try {
            return dumpModuleAttempt(mod);
        } catch (e) {
            console.log('[!] ' + mod.name + ': 시도 ' + attempt + '/3 실패 - ' + e);
        }
    }
    console.log('[-] ' + mod.name + ': 3회 재시도 후에도 실패, 원본(암호화 상태)으로 남습니다.');
    return null;
}

var LC_ENCRYPTION_INFO_64 = 0x2C;
var LC_ENCRYPTION_INFO = 0x21;

function dumpModuleAttempt(mod) {
    try {
        var fp = fopen(Memory.allocUtf8String(mod.path), Memory.allocUtf8String('rb'));
        if (fp.isNull()) {
            console.log('[-] ' + mod.name + ': fopen 실패');
            return null;
        }
        fseek(fp, 0, 2);
        var sz = ftell(fp).toNumber();
        fseek(fp, 0, 0);
        var buf = Memory.alloc(sz);
        fread(buf, 1, sz, fp);
        fclose(fp);

        var magic = buf.readU32();
        if (magic !== 0xfeedfacf && magic !== 0xcafebabe && magic !== 0xbebafeca) {
            console.log('[-] ' + mod.name + ': Mach-O magic 불일치, 스킵');
            return null;
        }

        var ncmds = buf.add(16).readU32();
        var off = 32, cryptCmd = null;
        for (var i = 0; i < ncmds; i++) {
            var cmd = buf.add(off).readU32();
            var csz = buf.add(off + 4).readU32();
            if (cmd === LC_ENCRYPTION_INFO_64 || cmd === LC_ENCRYPTION_INFO) {
                cryptCmd = off;
                break;
            }
            off += csz;
            if (csz === 0) break;
        }

        var wasEncrypted = false;
        if (cryptCmd !== null) {
            var cid = buf.add(cryptCmd + 16).readU32();
            if (cid !== 0) {
                wasEncrypted = true;
                var coff = buf.add(cryptCmd + 8).readU32();
                var csize = buf.add(cryptCmd + 12).readU32();
                try {
                    var live = mod.base.add(coff).readByteArray(csize);
                    buf.add(coff).writeByteArray(live);
                    buf.add(cryptCmd + 16).writeU32(0);
                    console.log('[+] ' + mod.name + ': 복호화 완료');
                } catch (e) {
                    console.log('[-] ' + mod.name + ': 메모리 읽기 실패 - ' + e);
                    return null;
                }
            }
        }
        if (!wasEncrypted) {
            console.log('[*] ' + mod.name + ': 원래 암호화 안 됨');
        }

        var outPath = WORK_DIR + '/decrypted_' + mod.name.replace(/[^a-zA-Z0-9._-]/g, '_');
        var ofp = fopen(Memory.allocUtf8String(outPath), Memory.allocUtf8String('wb'));
        if (ofp.isNull()) {
            console.log('[-] ' + mod.name + ': 출력 파일 생성 실패');
            return null;
        }
        fwrite(buf, 1, sz, ofp);
        fclose(ofp);
        console.log('[+] ' + mod.name + ': 저장 완료 (' + sz + ' bytes)');
        return outPath;
    } catch (e) {
        console.log('[-] ' + mod.name + ' 처리 중 예외: ' + e);
        return null;
    }
}

console.log('[*] 앱이 초기화되어 프레임워크들이 메모리에 로드될 때까지 5초 대기...');
setTimeout(function () {
try {
    console.log('[*] 작업 폴더 준비');
    mkdirp(WORK_DIR);
    console.log('[*] 작업 폴더 생성 시도 완료');

    var modules = Process.enumerateModules();
    var appBundleRe = /\/var\/containers\/Bundle\/Application\//;

    var mainMod = null;
    for (var m = 0; m < modules.length; m++) {
        var mod = modules[m];
        if (appBundleRe.test(mod.path) && mod.path.indexOf('.app/Frameworks/') === -1
            && /\.app\/[^\/]+$/.test(mod.path)) {
            mainMod = mod;
            break;
        }
    }
    if (!mainMod) {
        mainMod = modules.find(function (mod) { return appBundleRe.test(mod.path); });
    }
    if (!mainMod) throw new Error('메인 모듈을 찾지 못함.');
    console.log('[*] 메인 모듈: ' + mainMod.name + ' @ ' + mainMod.path);

    var decrypted = {};
    var targets = modules.filter(function (mod) {
        return mod === mainMod || appBundleRe.test(mod.path);
    });
    console.log('[*] 처리 대상 모듈 수: ' + targets.length);

    // NIMO에서 특정 프레임워크가 강력한 메모리 보호로 크래시를 유발하면
    // 여기에 모듈명을 추가해서 건너뛸 수 있음 (예: ['mTransKeyFramework'])
    var SKIP_MODULES = [];

    targets.forEach(function (mod) {
        if (SKIP_MODULES.indexOf(mod.name) !== -1) {
            console.log('--- 건너뜀 (알려진 크래시 유발 모듈): ' + mod.name + ' ---');
            return;
        }
        console.log('--- 처리 중: ' + mod.name + ' ---');
        var out = dumpModule(mod);
        if (out) decrypted[mod.name] = out;
    });
    console.log('[*] 복호화 완료된 모듈 수: ' + Object.keys(decrypted).length);

    var appPath = null;
    var idx = mainMod.path.indexOf('.app/');
    if (idx !== -1) {
        appPath = mainMod.path.substring(0, idx + 4);
    } else {
        var mm = mainMod.path.match(/(.*\.app)/);
        if (mm) appPath = mm[1];
    }
    if (!appPath) throw new Error('.app 경로를 찾을 수 없음.');
    var appName = appPath.split('/').pop().replace('.app', '');
    console.log('[*] 앱 번들: ' + appPath);

    // 순수 C API로 재귀 복사 (암호화 해제된 파일로 교체하면서)
    var payloadDir = WORK_DIR + "/Payload";
    var payloadApp = payloadDir + "/" + appName + ".app";
    mkdirp(payloadDir);

    // 파일명 기준 교체 맵 구성 (메인 실행파일 + 프레임워크들)
    var overrideMap = {};
    Object.keys(decrypted).forEach(function (modName) {
        overrideMap[modName] = decrypted[modName];
    });

    console.log('[*] 재귀 복사 시작 (복호화본 자동 교체 포함)...');
    var copiedCount = copyRecursiveWithOverride(appPath, payloadApp, overrideMap);
    console.log('[*] 복사된 파일 수: ' + copiedCount);

    console.log('');
    console.log('========================================');
    console.log('[+] Payload 폴더 생성 완료 (압축은 기기에서 하지 않음)');
    console.log('    경로: ' + payloadDir);
    console.log('');
    console.log('다음 단계 (PC에서):');
    console.log('  1. Filza에서 ' + payloadDir + ' 폴더로 이동');
    console.log('  2. Payload 폴더 압축(Zip)');
    console.log('  3. PC로 Export 후 확장자 .ipa 로 변경');
    console.log('========================================');

} catch (e) {
    console.log('[-] 치명적 오류: ' + e);
    console.log(e.stack);
}

console.log('[*] 스크립트 실행 완료');
}, 5000); // setTimeout 5초 지연 끝
