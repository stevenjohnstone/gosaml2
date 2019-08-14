package samlfuzz

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	rawMetadata = `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor entityID="http://www.okta.com/exk133onomIuOW98z357" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAWxzAwX1MA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi05MDUyNTExHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTkwODA4MjA1MzMzWhcNMjkwODA4MjA1NDMzWjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtOTA1MjUxMRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
m+ZZF6aEG6ehLLIV6RPA+i1z6ss3HBG2bZD3efwKCDDXYUkp59AE7JsjVHMtpJPHhzHuScuHDMlu
HmkBQTW7j9XpnaRn8SfZXkwlCUHTo+HAC9lwbQxO4d4wnwgnm6FAjm1I/gbfFAobd8BR9pDxHuXE
MQ0DtQu/W3WbDUrz/bhSxPJAoVy2koQn9G0y3unm7eRwYWHeuW6GdPWV2szTtDS0c3qtUXVF5Ugg
iQYlwQu6xkfy4l8iGJL7ETa2BmJzwCFecMIct87SqNhYQwCBH54MBaHcaSsCKyimNvMY9B7RmC+H
4+awePPA1q3R/UQ3Pfom8mx6yDdKIWqlkG3MsQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAiURCZ
P4oJWcf1o5nm4yG15UH01g/S6Y4OUWMi6BFJy9fCrJ0h/2BZKi68SQ0uMAbdK6anxCzq3Rr5MSzW
OWPQ1Zljn3LGPsiTFdFca/GVRen5IYQ7Dr2Mvhtm+QVscEY9TDjtETbTAHEVEjwXmB21wtdIhizv
sQS7wz0A8LV+Atpbev45RiV6COmB6T6vJuFQ7ZsDZMSHZriTYiETTJvHBGd7PtbCxYNc6LRB2JDb
wlekRhVEjR0UhnM+nn2sqqbv7tDEPs63lZSDXCnR1PhscHrEuQ04rHI3OL0gCULVQFvJrj85IAZF
1QQuGUK8ozfOyFpQWAJUW71INnF/SLWv</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dev-905251.okta.com/app/medev905251_test_1/exk133onomIuOW98z357/sso/saml"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://dev-905251.okta.com/app/medev905251_test_1/exk133onomIuOW98z357/sso/saml"/></md:IDPSSODescriptor></md:EntityDescriptor>`
	timeString = "2019-08-12T12:00:52.718Z"
)

func newServiceProvider() *saml2.SAMLServiceProvider {
	metadata := &types.EntityDescriptor{} // may need to support EntityDescriptors (plural)
	if err := xml.Unmarshal([]byte(rawMetadata), metadata); err != nil {
		panic(err)
	}

	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}

	for _, kd := range metadata.IDPSSODescriptor.KeyDescriptors {
		for _, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if xcert.Data == "" {
				panic("nope")
			}
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err != nil {
				panic(err)
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				panic(err)
			}

			certStore.Roots = append(certStore.Roots, idpCert)
		}
	}

	SSOs := metadata.IDPSSODescriptor.SingleSignOnServices

	tenantURI := "test.example.com"

	fakeTime, err := time.Parse(time.RFC3339, timeString)
	if err != nil {
		panic(err)
	}

	clock := dsig.NewFakeClockAt(fakeTime)

	return &saml2.SAMLServiceProvider{
		Clock:                       clock,
		IdentityProviderSSOURL:      SSOs[0].Location,
		IdentityProviderIssuer:      metadata.EntityID,
		ServiceProviderIssuer:       tenantURI,
		AssertionConsumerServiceURL: "https://127.0.0.1/login",
		SignAuthnRequests:           true,
		AudienceURI:                 tenantURI,
		IDPCertificateStore:         &certStore,
		ValidateEncryptionCert:      true,
	}
}
