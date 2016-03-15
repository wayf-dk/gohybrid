package main

import (
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/lMDQ"
	"log"
)

const (
	HUB_OP_MDQ = "/home/mz/hub_ops.mddb"
)

var (
	_      = log.Println
	hub_op *lMDQ.MDQ

	sourceResponse = gosaml.NewXp([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_336333b557cf99d44124c2c2b02b1cc2d4efb4fe2c"
                Version="2.0"
                IssueInstant="2016-02-02T21:33:10Z"
                Destination="https://wayf.wayf.dk/module.php/saml/sp/saml2-acs.php/wayf.wayf.dk"
                InResponseTo="_be2b06534490f9b658487041f1f011348c2834f8aa"
                >
    <saml:Issuer>https://wayf.ait.dtu.dk/saml2/idp/metadata.php</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
            <ds:Reference URI="#_336333b557cf99d44124c2c2b02b1cc2d4efb4fe2c">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                <ds:DigestValue>CLUJqLbuMsvHggz9sqJqm5PRjBE=</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>WKizpTmuMFUN3jv5c1DC4v7XVDOv4i8VrbcF9BCWNGb8BhMpVSar+Z6cwaL91fCtNwrAwq5quloImTjkjWcHi7XY2YEVgC2C3IB7yulhkkz8RxbI6HoLT04wjXcv6PW6kpZQszCMw5Y9zliRuRSk1b90nzuUhvEJWh3v3zFRR52E6jhpwW277ANMHK5AOWTtYuWfocmy6J9JPOKPlxs1fRbO1y9X9+tJ7jABltNMYfXJSoblsFGag/nAadg8ChuDsxzQ+ZNnBRjLjf6+TWclqVj1W7M6hDWJRpAHUotvMYRh2/wpvRzGx30mEcMOkgGP5a21A4BGWBIPJGA5Z6oi5Q==</ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>MIIEszCCA5ugAwIBAgIQBuU97081jlKyFb1aYH7wSTANBgkqhkiG9w0BAQUFADA2MQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEgU1NMIENBMB4XDTExMTIxMzAwMDAwMFoXDTE0MTIxMjIzNTk1OVowgY4xCzAJBgNVBAYTAkRLMRAwDgYDVQQIEwdEZW5tYXJrMRQwEgYDVQQHEwtLZ3MuIEx5bmdieTEoMCYGA1UEChMfVGVjaG5pY2FsIFVuaXZlcnNpdHkgb2YgRGVubWFyazETMBEGA1UECxMKSVQgU2VydmljZTEYMBYGA1UEAxMPd2F5Zi5haXQuZHR1LmRrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA18irEcMKn0RAI8+kxMKMj1vpESz3qLgcILOmzGaHkYCYsiUtAqrHTsmOUYdnE+BfWGEFsngneCoMW/Ct34YCj9CCl9yNqNRXXHnr7+ASMipB7aPODaAfOlxC/W+QNxOgkwfUAcKKA/B2nJ56uPUdtrM3OyQvtcOdkEiCrMTZKb/T5BDOXhM/IeDd2pTPiJUE5WwzanW0RXP7EmLQkygTTFcb2Fh0ARQ+hdZV200U/ERI5MDGj5IR/lurclKcbP9Bdw0/bgwAfVx7bf+XpuxdQN54NuB91Y7kYIiFT66qkN7ST/ZQjdZqU2F5uAtxdCaSTd2taSgKwoClOX4t32QGBwIDAQABo4IBYjCCAV4wHwYDVR0jBBgwFoAUDL2TaAzz3qujSWsrN1dH6pDjue0wHQYDVR0OBBYEFG3N9C92Cr7eyc1EWE4bY+rcdDReMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAYBgNVHSAEETAPMA0GCysGAQQBsjEBAgIdMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwudGNzLnRlcmVuYS5vcmcvVEVSRU5BU1NMQ0EuY3JsMG0GCCsGAQUFBwEBBGEwXzA1BggrBgEFBQcwAoYpaHR0cDovL2NydC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xDQS5jcnQwJgYIKwYBBQUHMAGGGmh0dHA6Ly9vY3NwLnRjcy50ZXJlbmEub3JnMBoGA1UdEQQTMBGCD3dheWYuYWl0LmR0dS5kazANBgkqhkiG9w0BAQUFAAOCAQEAmWq3MGe1fKFbmtPYc77grgVEi+n5jJHFHKFv/RTCqVrpLE52Z+wKT15HtKQ1ZfQ0hRvoPcmgDzWj1gc1Y33fG/VYxhJNN7TNwxm61PWpgHDaU63KkPxli6oY6DnKixn4QY6tAmEykB88T2qlj2kYGTBPMj5ndHHKVk9QTVcAsTSI1rXrCjtehtN9my2OFVEy7yapM9d6RO7NjxMJnmnqjjiZoRtgmOSOqCXLpn3bAEqzmdTnn8VNS2i8B1tNWOf4nFpoTLhEuOR4n8MwvA+/mf9uknKyvWOysDsBEjM+M1IG25DzC6T+aYx27niBhygDOFRLI+gIr3Odb9ODe+2yqw==</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </samlp:Status>
    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                    xmlns:xs="http://www.w3.org/2001/XMLSchema"
                    ID="_c5897a405e2fe06cfb8212f22ae143f949a0e18f2b"
                    Version="2.0"
                    IssueInstant="2016-02-02T21:33:10Z"
                    >
        <saml:Issuer>https://wayf.ait.dtu.dk/saml2/idp/metadata.php</saml:Issuer>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
                <ds:Reference URI="#_c5897a405e2fe06cfb8212f22ae143f949a0e18f2b">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                    <ds:DigestValue>XnR0pWAy72jA02bAXqjAUmwa9RU=</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>n9xvr50GYOtx3G068EeD6o2F5PPHttEuxZYBeUwzcNr8fuCQue9Ee3uAcuWYGvq2BcylCOyubYqNyqh9aACK0Eewtn0cJoVP0mtrmTXBbn5wFwPpodRM5Vk08t/+rxKxT03kyfaVyHy0IdERDDgtNbY49nIQXdgiSD+pEizqrjbKh8UXXyX/0oM+q7u1FuhQpPt3vx8DWtaiz5eekoTfIjki87agd+cSJT92uhQq3rBRmQadjGGVpVrK/VHjExHa5ar9N+8xcps/ml8QqVlzK8Jkd9WFsIsKv5CEYJdVn3LlokHm2OobRdw2/F0Wa2FN1mzWxQY6amaBqx3jygd0Jg==</ds:SignatureValue>
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>MIIEszCCA5ugAwIBAgIQBuU97081jlKyFb1aYH7wSTANBgkqhkiG9w0BAQUFADA2MQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEgU1NMIENBMB4XDTExMTIxMzAwMDAwMFoXDTE0MTIxMjIzNTk1OVowgY4xCzAJBgNVBAYTAkRLMRAwDgYDVQQIEwdEZW5tYXJrMRQwEgYDVQQHEwtLZ3MuIEx5bmdieTEoMCYGA1UEChMfVGVjaG5pY2FsIFVuaXZlcnNpdHkgb2YgRGVubWFyazETMBEGA1UECxMKSVQgU2VydmljZTEYMBYGA1UEAxMPd2F5Zi5haXQuZHR1LmRrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA18irEcMKn0RAI8+kxMKMj1vpESz3qLgcILOmzGaHkYCYsiUtAqrHTsmOUYdnE+BfWGEFsngneCoMW/Ct34YCj9CCl9yNqNRXXHnr7+ASMipB7aPODaAfOlxC/W+QNxOgkwfUAcKKA/B2nJ56uPUdtrM3OyQvtcOdkEiCrMTZKb/T5BDOXhM/IeDd2pTPiJUE5WwzanW0RXP7EmLQkygTTFcb2Fh0ARQ+hdZV200U/ERI5MDGj5IR/lurclKcbP9Bdw0/bgwAfVx7bf+XpuxdQN54NuB91Y7kYIiFT66qkN7ST/ZQjdZqU2F5uAtxdCaSTd2taSgKwoClOX4t32QGBwIDAQABo4IBYjCCAV4wHwYDVR0jBBgwFoAUDL2TaAzz3qujSWsrN1dH6pDjue0wHQYDVR0OBBYEFG3N9C92Cr7eyc1EWE4bY+rcdDReMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAYBgNVHSAEETAPMA0GCysGAQQBsjEBAgIdMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwudGNzLnRlcmVuYS5vcmcvVEVSRU5BU1NMQ0EuY3JsMG0GCCsGAQUFBwEBBGEwXzA1BggrBgEFBQcwAoYpaHR0cDovL2NydC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xDQS5jcnQwJgYIKwYBBQUHMAGGGmh0dHA6Ly9vY3NwLnRjcy50ZXJlbmEub3JnMBoGA1UdEQQTMBGCD3dheWYuYWl0LmR0dS5kazANBgkqhkiG9w0BAQUFAAOCAQEAmWq3MGe1fKFbmtPYc77grgVEi+n5jJHFHKFv/RTCqVrpLE52Z+wKT15HtKQ1ZfQ0hRvoPcmgDzWj1gc1Y33fG/VYxhJNN7TNwxm61PWpgHDaU63KkPxli6oY6DnKixn4QY6tAmEykB88T2qlj2kYGTBPMj5ndHHKVk9QTVcAsTSI1rXrCjtehtN9my2OFVEy7yapM9d6RO7NjxMJnmnqjjiZoRtgmOSOqCXLpn3bAEqzmdTnn8VNS2i8B1tNWOf4nFpoTLhEuOR4n8MwvA+/mf9uknKyvWOysDsBEjM+M1IG25DzC6T+aYx27niBhygDOFRLI+gIr3Odb9ODe+2yqw==</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </ds:Signature>
        <saml:Subject>
            <saml:NameID SPNameQualifier="https://wayf.wayf.dk"
                         Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
                         >_470f3e8bd3430425c2a962310b4a8d0a79d3fcf23e</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="2016-02-02T21:38:10Z"
                                              Recipient="https://wayf.wayf.dk/module.php/saml/sp/saml2-acs.php/wayf.wayf.dk"
                                              InResponseTo="_be2b06534490f9b658487041f1f011348c2834f8aa"
                                              />
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="2016-02-02T21:32:40Z"
                         NotOnOrAfter="2016-02-02T21:38:10Z"
                         >
            <saml:AudienceRestriction>
                <saml:Audience>https://wayf.wayf.dk</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="2016-02-02T21:09:08Z"
                             SessionNotOnOrAfter="2016-02-03T05:33:10Z"
                             SessionIndex="_ba4740cce62d7b571aa13ff862d1242b37984f4d82"
                             >
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
            <saml:Attribute Name="uid"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">madpe</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="mail"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">madpe@dtu.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="gn"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Mads Freek</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="sn"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Petersen</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="cn"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Mads Freek Petersen</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="preferredLanguage"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">da-DK</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="organizationName"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Danmarks Tekniske Universitet</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonPrincipalName"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">madpe@dtu.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonPrimaryAffiliation"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">staff</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonScopedAffiliation"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">staff@just.testing.dtu.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="schacPersonalUniqueID"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408586234</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonAssurance"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">2</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonEntitlement"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:tcs:escience-user</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>
`))
)

func ExampleWayfAttributeHandler() {
	hub_md := gosaml.NewXp(wayfrequestedattributes)
	idp := sourceResponse.Query1(nil, "/samlp:Response/saml:Issuer")

	hub_op, _ := new(lMDQ.MDQ).Open(HUB_OP_MDQ)
	idp_md, _, _ := hub_op.MDQ(idp)
	WayfAttributeHandler(idp_md, hub_md, sourceResponse)
	log.Println(sourceResponse.Pp())
	// output: hi
}
