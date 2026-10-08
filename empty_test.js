// 아무 후킹도 안 하는 빈 스크립트.
// 이것만으로도 터치 무반응/시스템 전체 버벅임이 재현되면,
// 우리 스크립트 로직 문제가 아니라 Frida 자체(또는 이 기기와의 궁합)
// 문제라는 게 확정됨.
console.log("[*] empty test script loaded - 아무 후킹도 안 함");
setInterval(function () {
    console.log("[*] alive: " + new Date().toISOString());
}, 3000);
