// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	rand2 "math/rand"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var userAndHostname string

func init() {
	u, err := user.Current()
	if err == nil {
		userAndHostname = u.Username + "@"
	}
	if h, err := os.Hostname(); err == nil {
		userAndHostname += h
	}
	if err == nil && u.Name != "" && u.Name != u.Username {
		userAndHostname += " (" + u.Name + ")"
	}
}

func (m *mkcert) makeCert(hosts []string) {
	priv, err := m.generateKey(false)
	fatalIfErr(err, "failed to generate certificate key")
	pub := priv.(crypto.Signer).Public()

	tpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"gtestcert development certificate"},
			OrganizationalUnit: []string{userAndHostname},
			SerialNumber:       randomSerialNumber().String(),
		},
		PublicKey: pub,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(h); err == nil && email.Address == h {
			tpl.EmailAddresses = append(tpl.EmailAddresses, h)
		} else if uriName, err := url.Parse(h); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			tpl.URIs = append(tpl.URIs, uriName)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}

	// IIS (the main target of PKCS #12 files), only shows the deprecated
	// Common Name in the UI. See issue #115.
	if m.pkcs12 {
		tpl.Subject.CommonName = hosts[0]
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, tpl, priv)

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csr,
	})

	csrBlock, _ := pem.Decode(csrPEM)

	certDER, caIntermediateDER, caRootDER, err := makeCertFromGTestCA(rand.Reader, csrBlock, m)
	fatalIfErr(err, "failed to generate certificate")

	certFile, keyFile, p12File := m.fileNames(hosts)

	if !m.pkcs12 {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		caIntermediate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caIntermediateDER})
		certPEM = append(certPEM, caIntermediate...)
		caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caRootDER})
		certPEM = append(certPEM, caRoot...)

		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		fatalIfErr(err, "failed to encode certificate key")
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

		if certFile == keyFile {
			err = ioutil.WriteFile(keyFile, append(certPEM, privPEM...), 0600)
			fatalIfErr(err, "failed to save certificate and key")
		} else {
			err = ioutil.WriteFile(certFile, certPEM, 0644)
			fatalIfErr(err, "failed to save certificate")
			err = ioutil.WriteFile(keyFile, privPEM, 0600)
			fatalIfErr(err, "failed to save certificate key")
		}
	} else {
		domainCert, _ := x509.ParseCertificate(certDER)
		pfxData, err := pkcs12.Encode(rand.Reader, priv, domainCert, []*x509.Certificate{m.caCert}, "changeit")
		fatalIfErr(err, "failed to generate PKCS#12")
		err = ioutil.WriteFile(p12File, pfxData, 0644)
		fatalIfErr(err, "failed to save PKCS#12")
	}

	m.printHosts(hosts)

	if !m.pkcs12 {
		if certFile == keyFile {
			log.Printf("\nThe certificate and key are at \"%s\" ✅\n\n", certFile)
		} else {
			log.Printf("\nThe certificate is at \"%s\" and the key at \"%s\" ✅\n\n", certFile, keyFile)
		}
	} else {
		log.Printf("\nThe PKCS#12 bundle is at \"%s\" ✅\n", p12File)
		log.Printf("\nThe legacy PKCS#12 encryption password is the often hardcoded default \"changeit\" ℹ️\n\n")
	}

	cert, _ := x509.ParseCertificate(certDER)
	log.Printf("It will expire on %s 🗓\n\n", cert.NotAfter.Format("2 January 2006"))
}

func (m *mkcert) printHosts(hosts []string) {
	secondLvlWildcardRegexp := regexp.MustCompile(`(?i)^\*\.[0-9a-z_-]+$`)
	log.Printf("\nCreated a new certificate valid for the following names 📜")
	for _, h := range hosts {
		log.Printf(" - %q", h)
		if secondLvlWildcardRegexp.MatchString(h) {
			log.Printf("   Warning: many browsers don't support second-level wildcards like %q ⚠️", h)
		}
	}

	for _, h := range hosts {
		if strings.HasPrefix(h, "*.") {
			log.Printf("\nReminder: X.509 wildcards only go one level deep, so this won't match a.b.%s ℹ️", h[2:])
			break
		}
	}
}

func (m *mkcert) generateKey(rootCA bool) (crypto.PrivateKey, error) {
	if m.ecdsa {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if rootCA {
		return rsa.GenerateKey(rand.Reader, 3072)
	}
	return rsa.GenerateKey(rand.Reader, 2048)
}

func (m *mkcert) fileNames(hosts []string) (certFile, keyFile, p12File string) {
	defaultName := strings.Replace(hosts[0], ":", "_", -1)
	defaultName = strings.Replace(defaultName, "*", "_wildcard", -1)
	if len(hosts) > 1 {
		defaultName += "+" + strconv.Itoa(len(hosts)-1)
	}
	if m.client {
		defaultName += "-client"
	}

	certFile = "./" + defaultName + ".pem"
	if m.certFile != "" {
		certFile = m.certFile
	}
	keyFile = "./" + defaultName + "-key.pem"
	if m.keyFile != "" {
		keyFile = m.keyFile
	}
	p12File = "./" + defaultName + ".p12"
	if m.p12File != "" {
		p12File = m.p12File
	}

	return
}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")
	return serialNumber
}

func (m *mkcert) makeCertFromCSR() {
	csrPEMBytes, err := ioutil.ReadFile(m.csrPath)
	fatalIfErr(err, "failed to read the CSR")
	csrPEM, _ := pem.Decode(csrPEMBytes)
	if csrPEM == nil {
		log.Fatalln("ERROR: failed to read the CSR: unexpected content")
	}
	if csrPEM.Type != "CERTIFICATE REQUEST" &&
		csrPEM.Type != "NEW CERTIFICATE REQUEST" {
		log.Fatalln("ERROR: failed to read the CSR: expected CERTIFICATE REQUEST, got " + csrPEM.Type)
	}

	certDER, caIntermediateDER, caRootDER, err := makeCertFromGTestCA(rand.Reader, csrPEM, m)
	fatalIfErr(err, "failed to generate certificate")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	caIntermediate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caIntermediateDER})
	certPEM = append(certPEM, caIntermediate...)
	caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caRootDER})
	certPEM = append(certPEM, caRoot...)

	cert, err := x509.ParseCertificate(certDER)
	fatalIfErr(err, "failed to parse certificate")

	var hosts []string
	hosts = append(hosts, cert.DNSNames...)
	hosts = append(hosts, cert.EmailAddresses...)
	for _, ip := range cert.IPAddresses {
		hosts = append(hosts, ip.String())
	}
	for _, uri := range cert.URIs {
		hosts = append(hosts, uri.String())
	}
	certFile, _, _ := m.fileNames(hosts)

	err = ioutil.WriteFile(certFile, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644)
	fatalIfErr(err, "failed to save certificate")

	m.printHosts(hosts)

	log.Printf("\nThe certificate is at \"%s\" ✅\n\n", certFile)

	log.Printf("It will expire on %s 🗓\n\n", cert.NotAfter.Format("2 January 2006"))
}

func makeCertFromGTestCA(rand io.Reader, csrPEM *pem.Block, m *mkcert) ([]byte, []byte, []byte, error) {
	csr, err := x509.ParseCertificateRequest(csrPEM.Bytes)
	fatalIfErr(err, "failed to parse the CSR")
	fatalIfErr(csr.CheckSignature(), "invalid CSR signature")

	csrBase64 := base64.StdEncoding.EncodeToString(csrPEM.Bytes)

	raoPubKey := "MIIBCgKCAQEArOAiAygGTCy8dH6PI3WECfZBnxPnKHI/BtkkjnZKk6byqqWSF10kEO9rM3j/0vNioj6rTXJazKNDWytzriyNYjXzU9wXzc2nkPrIugQ3b16+sR7BHo7oTR22NZn7+8hxEKWJVv4GxZ9EB5DtGSMqfrbByaiDxwmniEUh1oWsGW7+RIVQmzTvZpThMGhOhXhRo5qqkptqFZ+YVQE1GtVE16dXt4G5ZcAShVkTFdjRCW/vSPv0MI+Xe+OK2fl4g3+0ARFgnPw1RFILfLBBIFA3O35oJdNm9zwN47wShQB2ceg8ZhkUi1tIlK1ncjmXj6Gm1NCv7YCPy1yf3WTT0NXrgQIDAQAB"
	uid := "TestUID" + strconv.Itoa(rand2.Intn(10000000-1000000)+1000000)

	var hosts []string
	hosts = append(hosts, csr.DNSNames...)
	hosts = append(hosts, csr.EmailAddresses...)
	for _, ip := range csr.IPAddresses {
		hosts = append(hosts, "ip:"+ip.String())
	}
	for _, uri := range csr.URIs {
		hosts = append(hosts, uri.String())
	}

	tbs := `
<TBS>
    <RAOPubKeyB64>` + raoPubKey + `</RAOPubKeyB64>
    <CustomizedData>
        <Data>
            <DataType>UNIQUE_ID</DataType>
            <DataValue>` + uid + `</DataValue>
        </Data>
        <Data>
            <DataType>GROUP_ID</DataType>
            <DataValue>6666</DataValue>
        </Data>
        <Data>
            <DataType>CERTTYPE_ID</DataType>
            <DataValue>666614</DataValue>
        </Data>
        <Data>
            <DataType>SubjectDN</DataType>
            <DataValue>C=TW,L=台中市,O=測試機關,CN=` + hosts[0] + `,SERIALNUMBER=` + randomSerialNumber().String() + `</DataValue>
        </Data>
        <Data>
            <DataType>CardNo</DataType>
            <DataValue>SW-6666-` + uid + `-` + time.Now().Format("2006/01/02-15:04:05") + `-0.` + strconv.Itoa(rand2.Intn(10000000-1000000)+1000000) + `</DataValue>
        </Data>
        <Data>
            <DataType>CERT_USAGE</DataType>
            <DataValue>digitalSignature|keyEncipherment</DataValue>
        </Data>
    </CustomizedData>
    <Extensions>
        <Ext>
            <OID>2.5.29.17</OID>
            <Value>` + strings.Join(hosts, ";;") + `</Value>
        </Ext>
        <Ext>
            <OID>2.5.29.15</OID>
            <Value>digitalSignature|keyEncipherment</Value>
        </Ext>
    </Extensions>
    <SubjectDirectoryAttributes>
        <SAttribute>
            <OID>2.16.886.1.100.2.1</OID>
            <Value>2.16.886.1.100.3.3.1</Value>
            <ValueType>oid</ValueType>
        </SAttribute>
    </SubjectDirectoryAttributes>
    <EECSRB64>` + csrBase64 + `</EECSRB64>
</TBS>
`

	whitespaces := regexp.MustCompile(`[\r\n\t ]`)
	tbs = whitespaces.ReplaceAllString(tbs, "")

	keyString := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCs4CIDKAZMLLx0
fo8jdYQJ9kGfE+cocj8G2SSOdkqTpvKqpZIXXSQQ72szeP/S82KiPqtNclrMo0Nb
K3OuLI1iNfNT3BfNzaeQ+si6BDdvXr6xHsEejuhNHbY1mfv7yHEQpYlW/gbFn0QH
kO0ZIyp+tsHJqIPHCaeIRSHWhawZbv5EhVCbNO9mlOEwaE6FeFGjmqqSm2oVn5hV
ATUa1UTXp1e3gbllwBKFWRMV2NEJb+9I+/Qwj5d744rZ+XiDf7QBEWCc/DVEUgt8
sEEgUDc7fmgl02b3PA3jvBKFAHZx6DxmGRSLW0iUrWdyOZePoabU0K/tgI/LXJ/d
ZNPQ1euBAgMBAAECggEABT4rp+X5iWtAqKWLMqWKbGkrkK8QR1CuLsdseXXW0Ysq
UECy2VqruKgDK7mlZAzZsp8VD8VqYasIpJng8XEEVWx6kYIy9lzQonfpmSMeOYZh
gQKEU7h8rPSMCWx+6PIZdDpZ+8F62/jWXcagWy8e536ESmjt/K4DNsG2etCdYVzI
qyle9kRDfdEqm08vMhcmawXvY/ARSS3gYWBLEC7bArExpBjguRzWS2r29VgBZfff
CUJ8ynux3On/MAYgugkgSa+xAvLyQicAeOGcjaN+wwnAUX78/HlULixudnF6Sm0o
i6IkiO9vmuh0aRL5Dzm9Yo0SHKt6SjNFvuou5xf8wQKBgQDcPFmO1RbfchbUOfFT
zQbnOR21K+pqEPlucrhID2/YGfoum2z/AV/6U7NyzTnibkKsN5ObbDpRLy9JNxi0
CZ8IX9m1A3JVSYV0sLOw3lhazLRp/HzpXbuJmN3/RZlq1Koe37l/TbA1oNJk2i7y
6J5++wYy7U+Mkt1sURItpYn+YQKBgQDI8uv12y31zE1fqgYuaB+PwxT0c5XBBt/H
PPZpn01pINvppVDkrBf6V/rspabpIrBjjJpKdSuvBFP27dLdbSMhXKZTO3Rzfg3Z
2ECL8V1gib0r5OvQQSTrXXkNs4IYe4cJUmj+9+kBiUXl6Gd90Ubf6P7Evn3MnDy2
/VSpNWXBIQKBgQDGFxYqramkE1dLTk6tJHW4FhyNb1GqU1g3KsJsNk5QHpVzxGLW
PyNX4l8+vC77Zldb1aVTn5YYnYs3nHIAxcKgYq5L7SyyX63FFoaZaHQqP4Nq7Sph
MOjUy4Wp7K0gdOYLXQnY4kTDB8MV6VVfMTIWXqzls6PgedzlZ0oleobTIQKBgADt
1pdxZvn+8tChaZvnUVYJ0dv7eNLGpFw4dO8yFFqLE1k2MXSNMyMuKvPTJD1psqUT
LldvyT7q5zR6DwKFEaeC1SYHXVd3WrsKG+pJuGPM3zoHuethkbkg2oFstgpE7+/k
GKYtIT+nkdIpS+kyAYDhg+QG+W/rvQAflbeejpThAoGAWKOfEaGR1he23mBQbNni
7J417QFG9IyUwjQypNh+Xxy6LxZ+Iqmc8GX+Bz7XaPK0+AoZojUdvABJU3j4vU7j
sBtErFji6FyxiuP/Gx/k9rlCSiDi1TDYYROIqfC/wqPXLZiu2t2FjaxLieBWzovd
/vK8fEC4KkuGk3UYYeAYTU4=
-----END PRIVATE KEY-----`

	block, _ := pem.Decode([]byte(keyString))
	parseResult, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	key := parseResult.(*rsa.PrivateKey)
	hashed := sha1.Sum([]byte(tbs))

	raoSign, err := rsa.SignPKCS1v15(rand, key, crypto.SHA1, hashed[:])
	fatalIfErr(err, "failed to sign tbs")

	raoSignBase64 := base64.StdEncoding.EncodeToString(raoSign)
	enrollXml := `<?xml version="1.0" encoding="UTF-8" ?>
<EnrollXML>
  ` + tbs + `
  <SigB64>` + raoSignBase64 + `</SigB64>
</EnrollXML>`

	xmlBase64 := base64.StdEncoding.EncodeToString([]byte(enrollXml))

	resp, err := http.PostForm("https://gtestca.nat.gov.tw/GeneralRA/general_ra_servlet", url.Values{"data": {xmlBase64}})
	fatalIfErr(err, "failed to create certificate from GTestCA")

	defer resp.Body.Close()
	responseXmlString, err := ioutil.ReadAll(resp.Body)
	fatalIfErr(err, "failed to parser GTestCA response")

	responseXml := ResponseXML{}
	err = xml.Unmarshal(responseXmlString, &responseXml)
	fatalIfErr(err, "failed to unmarshall response")

	if responseXml.RetCode.MajorRetCode != 0 || responseXml.RetCode.MinorRetCode != 0 {
		log.Fatalf("failed to generate certificate. MajorRetCode: %d, MinorRetCode: %d, RetMsg: %s",
			responseXml.RetCode.MajorRetCode, responseXml.RetCode.MinorRetCode, responseXml.RetCode.RetMsg)
	}

	certDER, err := base64.StdEncoding.DecodeString(responseXml.XMLBody.CertInfo.CertB64)
	fatalIfErr(err, "failed to decode signed certificate")

	caIntermediateDER, err := base64.StdEncoding.DecodeString(responseXml.XMLBody.CACertInfo.CACertB64)
	fatalIfErr(err, "failed to decode intermediate CA certificate")

	caRootDER, err := base64.StdEncoding.DecodeString(responseXml.XMLBody.CACertInfo.RootCACertB64)
	fatalIfErr(err, "failed to decode intermediate CA certificate")

	return certDER, caIntermediateDER, caRootDER, nil
}

type ResponseXML struct {
	XMLName xml.Name `xml:"ResponseXML"`
	Text    string   `xml:",chardata"`
	RetCode struct {
		Text         string `xml:",chardata"`
		TID          string `xml:"TID"`
		CATID        string `xml:"CA_TID"`
		MajorRetCode int    `xml:"MajorRetCode"`
		MinorRetCode int    `xml:"MinorRetCode"`
		RetMsg       string `xml:"RetMsg"`
	} `xml:"RetCode"`
	XMLBody struct {
		Text     string `xml:",chardata"`
		CertInfo struct {
			Text      string `xml:",chardata"`
			CertB64   string `xml:"CertB64"`
			CertSN    string `xml:"CertSN"`
			CertUsage string `xml:"CertUsage"`
		} `xml:"CertInfo"`
		CACertInfo struct {
			Text          string `xml:",chardata"`
			RootCACertB64 string `xml:"RootCACertB64"`
			CACertB64     string `xml:"CACertB64"`
		} `xml:"CACertInfo"`
	} `xml:"XMLBody"`
}

// loadCA will load or create the CA at CAROOT.
func (m *mkcert) loadCA() {
	if !pathExists(filepath.Join(m.CAROOT, rootName)) {
		m.newCA()
	}

	certPEMBlock, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read the CA certificate")
	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		log.Fatalln("ERROR: failed to read the CA certificate: unexpected content")
	}
	m.caCert, err = x509.ParseCertificate(certDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA certificate")
}

func (m *mkcert) newCA() {
	cert := []byte(`
-----BEGIN CERTIFICATE-----
MIICRTCCAcugAwIBAgIQa/z+iOa8FXjTkQPnnZ3ijDAKBggqhkjOPQQDAzBkMQsw
CQYDVQQGEwJUVzESMBAGA1UECgwJ6KGM5pS/6ZmiMUEwPwYDVQQDDDgo5ris6Kmm
55SoKSBHb3Zlcm5tZW50IFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBH
NDAeFw0xNjA0MzAxNjAwMDBaFw00MTA0MzAxNjAwMDBaMGQxCzAJBgNVBAYTAlRX
MRIwEAYDVQQKDAnooYzmlL/pmaIxQTA/BgNVBAMMOCjmuKzoqabnlKgpIEdvdmVy
bm1lbnQgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEc0MHYwEAYHKoZI
zj0CAQYFK4EEACIDYgAEy6sR/mXQjy2ZUvttZqGw/4kGKcEAiRph41BPeblTuhsf
eCMFfAL8Zb1MDPPkMzVrXW2/Wo/EKRKoE2ec/SdJStziIVbNfvqi3va/wliI6Mu7
x6Zf7Jo9Reh24Y3uxk0ro0IwQDAdBgNVHQ4EFgQUn86XTgj3GMOMklsIFiO11EjS
F0kwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwMD
aAAwZQIwdN4MJRMBy0oMW+DdA0TG7onvgDrkBkweUJZBsFSCdAVV0hKoq2MsqFdZ
ghDxkTsgAjEA+GLsR7EpdZzQas4jpzF+sBnNlh898Dsw5SCkXDAGZXQZPq3OS2eg
VI6Z+QNPpUaU
-----END CERTIFICATE-----
`)

	err := ioutil.WriteFile(filepath.Join(m.CAROOT, rootName), cert, 0644)
	fatalIfErr(err, "failed to save CA key")

	log.Printf("Installed the GTestRCA 💥\n")
}

func (m *mkcert) caUniqueName() string {
	return "mkcert development CA " + m.caCert.SerialNumber.String()
}
