
# gotpache-keytool

루트 인증서를 생성하고 이를 기반으로 자체 서명된 SSL 인증서를 발급하는 기능을 제공합니다. 
<br>

### Release Note

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

  implementation 'io.github.tricatch:gotpache-keytool:0.1.0'

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
   * gotpache-keytool-0.1.0.jar
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

## 라이선스
이 프로젝트는 MIT 라이선스를 따릅니다. 자세한 내용은 LICENSE 파일을 확인하세요.