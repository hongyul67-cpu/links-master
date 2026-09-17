📦 vendor — 남이 만든 라이브러리를 그대로 담아 둔 곳
============================================

■ 왜 여기에 두나요?
  예전에는 이 두 파일을 인터넷(cdn.jsdelivr.net)에서 그때그때 받아 썼습니다.
  그런데 두 가지가 걸렸습니다.

  1) 학교 망에서 그 주소가 막히면 [링크+QR 만들기]가 멈춥니다.
     (안내 문구는 뜨지만 QR은 못 만듭니다.)
  2) master.html 은 교사용 암호를 넣는 화면입니다.
     남의 서버에서 받아 온 코드가 그 화면에서 같이 돌면,
     그쪽 파일이 언젠가 바뀌었을 때 암호가 넘어갈 수 있습니다.

  그래서 파일을 저장소 안에 직접 넣고 여기서만 불러옵니다.
  이제 인터넷이 끊겨도, 학교 망이 막아도 QR이 만들어집니다.

■ 무엇이 들어 있나요?

  lz-string-1.5.0.min.js       공유 링크를 짧게 압축합니다
    출처   https://www.npmjs.com/package/lz-string  (1.5.0)
    라이선스 MIT — lz-string-LICENSE.txt 참고
    SHA-384 0d+Gr7vM4Drod8E3hXKgciWJSWbjD/opKLLygI9ktiWbuvlDwQLzU46wJ9s5gsp7

  qrcode-generator-1.4.4.js    QR 그림을 만듭니다
    출처   https://www.npmjs.com/package/qrcode-generator  (1.4.4)
    라이선스 MIT (파일 첫 줄에 적혀 있습니다 · Kazuhiko Arase)
    SHA-384 8FWZA6BGMXhsfO+BLtrJK0We6gg5o1JyO8xQm6peWDEUs17ACA5ziE/NIAkl9z2k

■ 고치지 마세요
  받은 그대로입니다. 여기 파일을 손대면 다음에 새 버전으로 바꿀 때 헷갈립니다.

■ 새 버전으로 바꾸고 싶다면
  1) npm pack lz-string@<버전>        ← .tgz 가 받아집니다
  2) 압축을 풀어 libs/lz-string.min.js 를 꺼냅니다
  3) 이 폴더에 <이름>-<버전>.min.js 로 넣습니다 (파일 이름에 버전을 넣으세요)
  4) 해시를 다시 적습니다:
       openssl dgst -sha384 -binary <파일> | openssl base64 -A
  5) master.html 의 <script src="vendor/..."> 줄을 새 파일 이름으로 고칩니다
  6) master.html 을 열어 [링크+QR 만들기]가 되는지 눈으로 확인합니다

  ※ 파일 이름에 버전이 들어 있어서 브라우저가 옛 파일을 계속 쓰는 일이 없습니다.
