
# gotpache-keytool

루트 인증서를 생성하고 이를 기반으로 자체 서명된 SSL 인증서를 발급하는 기능을 제공합니다. 
<br>

### Release Note

#### v0.1.1
* 64자를 넘는 도메인의 인증서 발급 (도메인은 SAN에, CN은 `gotpache-keytool`)
* RDN이 여러 개인 루트 인증서로 발급할 때 issuer 순서가 뒤집혀 검증에 실패하던 문제 수정
* 일련번호를 항상 양수로 발급
* SSL 인증서에 EKU(serverAuth), keyEncipherment 추가
* 도메인 문자열로 subject에 다른 속성이 들어가지 않도록 수정
* API는 그대로이며, 0.1.0으로 만든 루트 인증서(일련번호가 음수인 것 포함)도 다시 만들 필요 없이 사용 가능

#### v0.1.0
* 루트 인증서 발급
* SSL 인증서 발급


## 사용법
1. 단독으로 실행하여 루트, 도메인인증서를 생성하는 경우
<pre>
KeyTool Usage
-root {rootAlias} {rootPwd}
-ssl  {rootAlias} {rootPwd} {sslDomain} {sslPwd}
</pre>

2. 프로젝트에 라이브러리로 사용하는 경우(gradle)
<pre>
dependencies {

  implementation 'io.github.tricatch:gotpache-keytool:0.1.1'

}
</pre>

## KeyTool을 이용한 셀프사인 인증서 생성

1. 루트인증서 생성
<pre>
java -cp ./lib/* io.github.tricatch.gotpache.cert.KeyTool -root MyCA password

--- root certificate / privateKey ---
MyCA.crt
MyCA.key
</pre>


2. 도메인인증서 생성
<pre>
java -cp ./lib/* io.github.tricatch.gotpache.cert.KeyTool -ssl MyCA password foo.kr passwo
rd
--- ssl certificate / privateKey ---
foo.kr.crt
foo.kr.key
</pre>

#### Required
실행할 위치에 lib 폴더를 생성하고 Maven Repository에서 다운로드한다.
   * gotpache-keytool-0.1.1.jar
   * bcpkix-jdk18on-1.79.jar
   * bcprov-jdk18on-1.79.jar
   * bcutil-jdk18on-1.79.jar

## 어플리케이션에서 동적으로 인증서를 생성
<pre>
RootCertificateCreator rootCertificateCreator = new RootCertificateCreator();
SSLCertificateCreator sslCertificateCreator = new SSLCertificateCreator();

//루트인증서 생성
CertificateKeyPair rootCert = rootCertificateCreator.generateRootCertificate("MyCA");

//SSL 인증서 생성
CertificateKeyPair sslCert = sslCertificateCreator.generateSSLCertificate("foo.kr", rootCert.getCertificate(), rootCert.getPrivateKey());

KeyTool keyTool = new KeyTool();

//파일로 저장하기
keyTool.writeCertificate(sslCert.getCertificate(), path, fCa);
keyTool.writePublicKey(sslCert.getPublicKey(), path, fPubKey);
keyTool.writePrivateKey(sslCert.getPrivateKey(), path, fPriKey);
keyTool.writePrivateKey(sslCert.getPrivateKey(), "password", path, fPriKeyEnc);

//파일에서 읽기
X509Certificate certificate = keyTool.readCertificate(path, fCa);
PublicKey publicKey = keyTool.readPublicKey(path, fPubKey);
PrivateKey privateKey = keyTool.readPrivateKey(path, fPriKey);
PrivateKey privateKeyEnc = keyTool.readPrivateKey(path, fPriKeyEnc, "password" );
</pre>

## 발급되는 SSL 인증서
* subject: `CN=도메인`. 64자를 넘으면 `CN=gotpache-keytool`
* SAN: 도메인, `127.0.0.1`
* issuer: 루트 인증서의 subject를 인코딩 그대로 사용
* EKU: serverAuth / KU: digitalSignature, keyEncipherment
* 유효기간: 180일 (루트 인증서는 10년)

## 빌드
Gradle 8.11은 JDK 25에서 실행되지 않으므로 JDK 17로 실행한다(결과물은 Java 8 호환).
<pre>
JAVA_HOME={JDK 17 경로} ./gradlew test jar
</pre>

## 라이선스
이 프로젝트는 MIT 라이선스를 따릅니다. 자세한 내용은 LICENSE 파일을 확인하세요.