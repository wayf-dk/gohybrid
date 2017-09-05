package gohybrid

import (
	"fmt"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"log"
)

var (
	_ = log.Println

	requestedattributes = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://wayf.wayf.dk">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AttributeConsumingService index="0">
      <md:RequestedAttribute FriendlyName="sn" singular="true" must="true" Name="urn:oid:2.5.4.4"/>
      <md:RequestedAttribute FriendlyName="gn" singular="true" must="true" Name="urn:oid:2.5.4.42"/>
      <md:RequestedAttribute FriendlyName="cn" singular="true" must="true" Name="urn:oid:2.5.4.3"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrincipalName" singular="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="mail" Name="urn:oid:0.9.2342.19200300.100.1.3"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrimaryAffiliation" singular="true" must="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.5"/>
      <md:RequestedAttribute FriendlyName="organizationName" singular="true" must="true" Name="urn:oid:2.5.4.10"/>
      <md:RequestedAttribute FriendlyName="eduPersonAssurance" singular="true" must="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.11"/>
      <md:RequestedAttribute FriendlyName="schacPersonalUniqueID" Name="urn:oid:1.3.6.1.4.1.25178.1.2.15"/>
      <md:RequestedAttribute FriendlyName="schacCountryOfCitizenship" singular="true" Name="urn:oid:1.3.6.1.4.1.25178.1.2.5" />
      <md:RequestedAttribute FriendlyName="eduPersonScopedAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9" />
      <md:RequestedAttribute FriendlyName="preferredLanguage" Name="urn:oid:2.16.840.1.113730.3.1.39" />
      <md:RequestedAttribute FriendlyName="eduPersonEntitlement" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" />
      <md:RequestedAttribute FriendlyName="norEduPersonLIN" Name="urn:oid:1.3.6.1.4.1.2428.90.1.4" />
      <md:RequestedAttribute FriendlyName="schacHomeOrganization" computed="true" Name="urn:oid:1.3.6.1.4.1.25178.1.2.9" />
      <md:RequestedAttribute FriendlyName="eduPersonTargetedID" computed="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" />
      <md:RequestedAttribute FriendlyName="schacDateOfBirth" Name="urn:oid:1.3.6.1.4.1.25178.1.2.3" />
      <md:RequestedAttribute FriendlyName="schacYearOfBirth" Name="urn:oid:1.3.6.1.4.1.25178.1.0.2.3" />
      <md:RequestedAttribute FriendlyName="schacHomeOrganizationType" computed="true" Name="urn:oid:1.3.6.1.4.1.25178.1.2.10" />
      <md:RequestedAttribute FriendlyName="eduPersonAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" />
      <md:RequestedAttribute FriendlyName="displayName" Name="urn:oid:2.16.840.1.113730.3.1.241" />
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`

	sourceResponse = goxml.NewXp(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
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
`)

	nemloginResponse = goxml.NewXp(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Issuer>https://nemlogin.wayf.dk</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </samlp:Status>
    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                    xmlns:xs="http://www.w3.org/2001/XMLSchema"
                    ID="pfxc02d0111-e370-19a8-8099-5efd0c8ef45f"
                    Version="2.0"
                    IssueInstant="2017-09-04T08:06:05Z"
                    >
        <saml:Issuer>https://nemlogin.wayf.dk</saml:Issuer>
       <saml:AttributeStatement>
            <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                       >
                <saml:AttributeValue>CN=Anton Banon Cantonsen + SERIALNUMBER=PID:5666-1234-2-529868547821, O=Ingen organisatorisk tilknytning, C=DK</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                       >
                <saml:AttributeValue>someone@example.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.5.29.29"
                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                       >
                <saml:AttributeValue>CN=TRUST2408 OCES CA II, O=TRUST2408, C=DK</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.1466.115.121.1.8"
                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                       >
                <saml:AttributeValue>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</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="dk:gov:saml:Attribute:AssuranceLevel"
                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                       >
                <saml:AttributeValue>3</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3"
                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                       >
                <saml:AttributeValue>someone@example.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="dk:nemlogin:saml:Attribute:IdPSessionIndex"
                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                       >
                <saml:AttributeValue>8D-54-F1-F9-AD-67-D8-65-6D-5A-58-AD-9F-F2-E7-92-5E-72-82-62</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.5.4.4"
                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                       >
                <saml:AttributeValue/>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.5.4.3"
                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                       >
                <saml:AttributeValue>Anton Banon Cantonsen</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.5.4.10"
                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                       >
                <saml:AttributeValue>Ingen organisatorisk tilknytning</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="dk:gov:saml:Attribute:PidNumberIdentifier"
                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                       >
                <saml:AttributeValue>9208-2002-2-941238474441</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.5.4.5"
                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                       >
                <saml:AttributeValue>539B4CDA</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.1"
                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                       >
                <saml:AttributeValue>PID:5666-1234-2-529868547821</saml:AttributeValue>
                <saml:AttributeValue>PID:5666-1234-2-529868547821</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="dk:gov:saml:Attribute:CprNumberIdentifier"
                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                       >
                <saml:AttributeValue>2408586234</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="cn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
                <saml:AttributeValue>Just Testing</saml:AttributeValue>
                <saml:AttributeValue>Just Testing</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>
`)
)

func ExampleMD() {
	mddtu := md{entities: make(map[string]*goxml.Xp)}
	mddtu.entities["https://wayf.ait.dtu.dk/saml2/idp/metadata.php"] = idp_md
	_, x := mddtu.MDQ("https://wayf.ait.dtu.dk/saml2/idp/metadata.php")
	fmt.Println(x)
	_, x = mddtu.MDQ("x")
	fmt.Println(x)
	// output:
	// <nil>
	// Not found: x

}

func ExampleWayfAttributeHandler() {
	hub_md := goxml.NewXp(requestedattributes)

	WayfAttributeHandler(idp_md, hub_md, hub_md, sourceResponse)
	attributeStatement := sourceResponse.Query(nil, "//saml:AttributeStatement")[0]
	fmt.Println(attributeStatement.String())
	// output:
	// <saml:AttributeStatement>
	//             <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
	//                 <saml:AttributeValue xsi:type="xs:string">madpe</saml:AttributeValue>
	//             </saml:Attribute>
	//             <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="mail">
	//                 <saml:AttributeValue xsi:type="xs:string">madpe@dtu.dk</saml:AttributeValue>
	//             </saml:Attribute>
	//             <saml:Attribute Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="gn">
	//                 <saml:AttributeValue xsi:type="xs:string">Mads Freek</saml:AttributeValue>
	//             </saml:Attribute>
	//             <saml:Attribute Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="sn">
	//                 <saml:AttributeValue xsi:type="xs:string">Petersen</saml:AttributeValue>
	//             </saml:Attribute>
	//             <saml:Attribute Name="urn:oid:2.5.4.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="cn">
	//                 <saml:AttributeValue xsi:type="xs:string">Mads Freek Petersen</saml:AttributeValue>
	//             </saml:Attribute>
	//             <saml:Attribute Name="urn:oid:2.16.840.1.113730.3.1.39" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="preferredLanguage">
	//                 <saml:AttributeValue xsi:type="xs:string">da-DK</saml:AttributeValue>
	//             </saml:Attribute>
	//             <saml:Attribute Name="urn:oid:2.5.4.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="organizationName">
	//                 <saml:AttributeValue xsi:type="xs:string">Danmarks Tekniske Universitet</saml:AttributeValue>
	//             </saml:Attribute>
	//             <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="eduPersonPrincipalName">
	//                 <saml:AttributeValue xsi:type="xs:string">madpe@dtu.dk</saml:AttributeValue>
	//             </saml:Attribute>
	//             <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="eduPersonPrimaryAffiliation">
	//                 <saml:AttributeValue xsi:type="xs:string">staff</saml:AttributeValue>
	//             </saml:Attribute>
	//             <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="eduPersonScopedAffiliation">
	//                 <saml:AttributeValue xsi:type="xs:string">staff@just.testing.dtu.dk</saml:AttributeValue>
	//             </saml:Attribute>
	//             <saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.15" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="schacPersonalUniqueID">
	//                 <saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408586234</saml:AttributeValue>
	//             </saml:Attribute>
	//             <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.11" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="eduPersonAssurance">
	//                 <saml:AttributeValue xsi:type="xs:string">2</saml:AttributeValue>
	//             </saml:Attribute>
	//             <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="eduPersonEntitlement">
	//                 <saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:tcs:escience-user</saml:AttributeValue>
	//             </saml:Attribute>
	//         <saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.10" FriendlyName="schacHomeOrganizationType" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>urn:mace:terena.org:schac:homeOrganizationType:eu:higherEducationalInstitution</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.9" FriendlyName="schacHomeOrganization" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>dtu.dk</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:oid:2.16.840.1.113730.3.1.241" FriendlyName="displayName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>Mads Freek Petersen</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" FriendlyName="eduPersonTargetedID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>WAYF-DK-248f81f290134aae5d72f5a37e197af78748e633</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.3" FriendlyName="schacDateOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>18580824</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.0.2.3" FriendlyName="schacYearOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>1858</saml:AttributeValue></saml:Attribute><md:RequestedAttribute xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" FriendlyName="eduPersonAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" isRequired="true"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>member</saml:AttributeValue></md:RequestedAttribute><md:RequestedAttribute xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" FriendlyName="eduPersonScopedAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9" isRequired="true"><saml:AttributeValue>staff@dtu.dk</saml:AttributeValue><saml:AttributeValue>member@dtu.dk</saml:AttributeValue></md:RequestedAttribute></saml:AttributeStatement>
	//
}

func ExampleNemLoginAttributeHandler() {

	nemloginAttributeHandler(nemloginResponse)
	gosaml.AttributeCanonicalDump(nemloginResponse)
	fmt.Println(nemloginResponse.Doc.Dump(true))
	// output:
	// cn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     Mads Freek Petersen
	// dk:gov:saml:Attribute:AssuranceLevel urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     3
	// dk:gov:saml:Attribute:CprNumberIdentifier urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     2408586234
	// dk:gov:saml:Attribute:PidNumberIdentifier urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     9208-2002-2-941238474441
	// dk:nemlogin:saml:Attribute:IdPSessionIndex urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     8D-54-F1-F9-AD-67-D8-65-6D-5A-58-AD-9F-F2-E7-92-5E-72-82-62
	// eduPersonAssurance urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     3
	// eduPersonPrimaryAffiliation urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     member
	// eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     PID:9208-2002-2-941238474441@sikker-adgang.dk
	// gn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     Mads Freek
	// http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     mads@freekpetersen.dk
	// http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     CN=Mads Freek Petersen + SERIALNUMBER=PID:9208-2002-2-941238474441, O=Ingen organisatorisk tilknytning, C=DK
	// mail urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     mads@freekpetersen.dk
	// organizationName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     NemLogin
	// schacHomeOrganization urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     http://sikker-adgang.dk
	// schacPersonalUniqueID urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408586234
	// sn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     Petersen
	// urn:oid:0.9.2342.19200300.100.1.1 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     PID:9208-2002-2-941238474441
	//     PID:9208-2002-2-941238474441
	// urn:oid:0.9.2342.19200300.100.1.3 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     mads@freekpetersen.dk
	// urn:oid:1.3.6.1.4.1.1466.115.121.1.8 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     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
	// urn:oid:2.5.29.29 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     CN=TRUST2408 OCES CA II, O=TRUST2408, C=DK
	// urn:oid:2.5.4.10 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     Ingen organisatorisk tilknytning
	// urn:oid:2.5.4.3 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     Mads Freek Petersen
	// urn:oid:2.5.4.4 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//
	// urn:oid:2.5.4.5 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     539B4CDA
}
