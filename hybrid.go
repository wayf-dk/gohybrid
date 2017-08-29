/* Hybrid implements the WAYF hybrid architecture
   - support for RelayState
   - does not seem to work: incl. Capitalization content-security-policy: referrer no-referrer;
   - redo no-referer - current version does not work !!!
   - MDQ lookup by location also for hub md
   - Trusted proxy
   - wayf:wayf i hub_ops metadata
        - AttributeNameFormat for Krib -> WAYF SPS - ie if none -> repeat wayf error both formats but error
        - schacHomeOrganization
        - schacHomeOrganizationType
   - collect schema errors
   - illegal attributes from IdP - ignore or provoke error
*/

package main

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	//    "github.com/spacemonkeygo/openssl"
	"html/template"
	"log"
	"net/http"
	"net/url"
	//	"os"
	//	"os/signal"
	"regexp"
	//	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	//	"syscall"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"time"
)

type (
	formdata struct {
		Acs          string
		Samlresponse string
	}

	appHandler func(http.ResponseWriter, *http.Request) error

	idpsppair struct {
		idp string
		sp  string
	}

	md struct {
	    entities map[string]*goxml.Xp
	}
)

const (
	idpCertQuery = `./md:IDPSSODescriptor/md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`
	certPath     = "/etc/ssl/wayf/signing/"

	postformtemplate = `<html>
<body onload="document.forms[0].submit()">
<form action="{{.Acs}}" method="POST">
<input type="hidden" name="SAMLResponse" value="{{.Samlresponse}}" />
<input type="submit" value="Submit" />
</form>
</body>
</html>`

	basic      = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	uri        = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	transient  = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

var (
	_ = log.Printf // For debugging; delete when done.
	_ = fmt.Printf

	remap = map[string]idpsppair{
		"https://nemlogin.wayf.dk": idpsppair{"https://saml.nemlog-in.dk", "https://nemlogin.wayf.dk"},
	}

	config = map[string]string{
		"HYBRID_DOMAIN":        "wayf.dk",
		"HYBRID_HUB":           "https://wayf.wayf.dk",
		"HYBRID_DISCOVERY":     "https://ds.wayf.dk/?",
		"HYBRID_INTERFACE":     "0.0.0.0:443",
		"HYBRID_HTTPS_KEY":     "/etc/ssl/wayf/private/wildcard.test.lan.key",
		"HYBRID_HTTPS_CERT":    "/etc/ssl/wayf/certs/wildcard.test.lan.pem",
		"HYBRID_PUBLIC":        "src/github.com/wayf-dk/gohybrid/public",
		"HYBRID_PUBLIC_PREFIX": "/DS/",
		"HYBRID_SSO_SERVICE":   "/saml2/idp/SSOService2.php",
		"HYBRID_ACS":           "/module.php/saml/sp/saml2-acs.php/wayf.wayf.dk",
		"HYBRID_BIRK":          "/birk.php/",
		"HYBRID_KRIB":          "/krib.php/",
		"WAYFSP_SP":            "wayfsp.wayf.dk/",
		"WAYFSP_ACS":           "wayfsp.wayf.dk/ss/module.php/saml/sp/saml2-acs.php/default-sp",
	}

	contextmutex   sync.RWMutex
	context        = make(map[*http.Request]map[string]string)
	bify           = regexp.MustCompile("^(https?://)(.*)$")
	debify         = regexp.MustCompile("^(https?://)(?:(?:birk|krib)\\.wayf.dk/(?:birk|krib)\\.php/)(.+)$")
	stdtiming      = gosaml.IdAndTiming{time.Now(), 4 * time.Minute, 4 * time.Hour, "", ""}
	postform       = template.Must(template.New("post").Parse(postformtemplate))
	elementsToSign = []string{"/samlp:Response/saml:Assertion"}

	hub, hub_ops, edugain md
	hubmd                 *goxml.Xp

	Wayfrequestedattributes = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://wayf.wayf.dk">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AttributeConsumingService index="0">
      <md:RequestedAttribute FriendlyName="sn" singular="true" must="true" Name="urn:oid:2.5.4.4" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="gn" singular="true" must="true" Name="urn:oid:2.5.4.42" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="cn" singular="true" must="true" Name="urn:oid:2.5.4.3" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrincipalName" singular="true" mandatory="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="mail" Name="urn:oid:0.9.2342.19200300.100.1.3" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrimaryAffiliation" singular="true" must="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.5" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="organizationName" singular="true" must="true" Name="urn:oid:2.5.4.10" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonAssurance" singular="true" must="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.11" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacPersonalUniqueID" Name="urn:oid:1.3.6.1.4.1.25178.1.2.15" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacCountryOfCitizenship" singular="true" Name="urn:oid:1.3.6.1.4.1.25178.1.2.5" isRequired="true" />
      <md:RequestedAttribute FriendlyName="eduPersonScopedAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9" isRequired="true" />
      <md:RequestedAttribute FriendlyName="preferredLanguage" Name="urn:oid:2.16.840.1.113730.3.1.39" isRequired="true" />
      <md:RequestedAttribute FriendlyName="eduPersonEntitlement" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" isRequired="true" />
      <md:RequestedAttribute FriendlyName="norEduPersonLIN" Name="urn:oid:1.3.6.1.4.1.2428.90.1.4" isRequired="true" />
      <md:RequestedAttribute FriendlyName="schacHomeOrganization" computed="true" Name="urn:oid:1.3.6.1.4.1.25178.1.2.9" isRequired="true" />
      <md:RequestedAttribute FriendlyName="eduPersonTargetedID" computed="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" isRequired="true" />
      <md:RequestedAttribute FriendlyName="schacDateOfBirth" Name="urn:oid:1.3.6.1.4.1.25178.1.2.3" isRequired="true" />
	  <md:RequestedAttribute FriendlyName="schacYearOfBirth" Name="urn:oid:1.3.6.1.4.1.25178.1.0.2.3" isRequired="true" />
	  <md:RequestedAttribute FriendlyName="schacHomeOrganizationType" computed="true" Name="urn:oid:1.3.6.1.4.1.25178.1.2.10" isRequired="true" />
	  <md:RequestedAttribute FriendlyName="eduPersonAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" isRequired="true" />
      <md:RequestedAttribute FriendlyName="displayName" Name="urn:oid:2.16.840.1.113730.3.1.241" isRequired="true" />
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`

	basic2uri = map[string]string{}

	idp_md = goxml.NewXp(`<?xml version="1.0"?>
<md:EntityDescriptor xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" xmlns:wayf="http://wayf.dk/2014/08/wayf" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:remd="http://refeds.org/metadata" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://wayf.ait.dtu.dk/saml2/idp/metadata.php" ID="WAYF000527">
  <md:Extensions xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
    <mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute">
      <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" Name="urn:oasis:names:tc:SAML:attribute:assurance-certification">
        <saml:AttributeValue>https://refeds.org/sirtfi</saml:AttributeValue>
      </saml:Attribute>
    </mdattr:EntityAttributes>
    <mdrpi:RegistrationInfo xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" registrationInstant="2012-02-03T13:34:44Z"/>
    <wayf:wayf xmlns:wayf="http://wayf.dk/2014/08/wayf">
      <wayf:active>yes</wayf:active>
      <wayf:AttributeNameFormat/>
      <wayf:eduGAIN>Yes</wayf:eduGAIN>
      <wayf:eid>527</wayf:eid>
      <wayf:env>prod</wayf:env>
      <wayf:federation>WAYF</wayf:federation>
      <wayf:federation>HUBIDP</wayf:federation>
      <wayf:icon>1328169026_dtu-janus.png</wayf:icon>
      <wayf:kalmar>1</wayf:kalmar>
      <wayf:modified>2017-05-09T12:31:13Z</wayf:modified>
      <wayf:redirect.sign>1</wayf:redirect.sign>
      <wayf:redirect.validate>1</wayf:redirect.validate>
      <wayf:revisionid>63</wayf:revisionid>
      <wayf:RegistrationInstant2>2012-02-03T13:34:44Z</wayf:RegistrationInstant2>
      <wayf:type>saml20-idp</wayf:type>
      <wayf:wayf_schacHomeOrganization>dtu.dk</wayf:wayf_schacHomeOrganization>
      <wayf:wayf_schacHomeOrganizationType>urn:mace:terena.org:schac:homeOrganizationType:eu:higherEducationalInstitution</wayf:wayf_schacHomeOrganizationType>
    </wayf:wayf>
  </md:Extensions>
  <md:IDPSSODescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:Extensions>
      <shibmd:Scope xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" regexp="false">dtu.dk</shibmd:Scope>
      <mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">
        <mdui:DisplayName xml:lang="da">Danmarks Tekniske Universitet</mdui:DisplayName>
        <mdui:DisplayName xml:lang="en">Technical University of Denmark</mdui:DisplayName>
      </mdui:UIInfo>
    </md:Extensions>
    <md:KeyDescriptor>
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIEszCCA5ugAwIBAgIQBuU97081jlKyFb1aYH7wSTANBgkqhkiG9w0BAQUFADA2MQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEgU1NMIENBMB4XDTExMTIxMzAwMDAwMFoXDTE0MTIxMjIzNTk1OVowgY4xCzAJBgNVBAYTAkRLMRAwDgYDVQQIEwdEZW5tYXJrMRQwEgYDVQQHEwtLZ3MuIEx5bmdieTEoMCYGA1UEChMfVGVjaG5pY2FsIFVuaXZlcnNpdHkgb2YgRGVubWFyazETMBEGA1UECxMKSVQgU2VydmljZTEYMBYGA1UEAxMPd2F5Zi5haXQuZHR1LmRrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA18irEcMKn0RAI8+kxMKMj1vpESz3qLgcILOmzGaHkYCYsiUtAqrHTsmOUYdnE+BfWGEFsngneCoMW/Ct34YCj9CCl9yNqNRXXHnr7+ASMipB7aPODaAfOlxC/W+QNxOgkwfUAcKKA/B2nJ56uPUdtrM3OyQvtcOdkEiCrMTZKb/T5BDOXhM/IeDd2pTPiJUE5WwzanW0RXP7EmLQkygTTFcb2Fh0ARQ+hdZV200U/ERI5MDGj5IR/lurclKcbP9Bdw0/bgwAfVx7bf+XpuxdQN54NuB91Y7kYIiFT66qkN7ST/ZQjdZqU2F5uAtxdCaSTd2taSgKwoClOX4t32QGBwIDAQABo4IBYjCCAV4wHwYDVR0jBBgwFoAUDL2TaAzz3qujSWsrN1dH6pDjue0wHQYDVR0OBBYEFG3N9C92Cr7eyc1EWE4bY+rcdDReMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAYBgNVHSAEETAPMA0GCysGAQQBsjEBAgIdMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwudGNzLnRlcmVuYS5vcmcvVEVSRU5BU1NMQ0EuY3JsMG0GCCsGAQUFBwEBBGEwXzA1BggrBgEFBQcwAoYpaHR0cDovL2NydC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xDQS5jcnQwJgYIKwYBBQUHMAGGGmh0dHA6Ly9vY3NwLnRjcy50ZXJlbmEub3JnMBoGA1UdEQQTMBGCD3dheWYuYWl0LmR0dS5kazANBgkqhkiG9w0BAQUFAAOCAQEAmWq3MGe1fKFbmtPYc77grgVEi+n5jJHFHKFv/RTCqVrpLE52Z+wKT15HtKQ1ZfQ0hRvoPcmgDzWj1gc1Y33fG/VYxhJNN7TNwxm61PWpgHDaU63KkPxli6oY6DnKixn4QY6tAmEykB88T2qlj2kYGTBPMj5ndHHKVk9QTVcAsTSI1rXrCjtehtN9my2OFVEy7yapM9d6RO7NjxMJnmnqjjiZoRtgmOSOqCXLpn3bAEqzmdTnn8VNS2i8B1tNWOf4nFpoTLhEuOR4n8MwvA+/mf9uknKyvWOysDsBEjM+M1IG25DzC6T+aYx27niBhygDOFRLI+gIr3Odb9ODe+2yqw==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://wayf.ait.dtu.dk/saml2/idp/SSOService.php"/>
  </md:IDPSSODescriptor>
  <md:Organization xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
    <md:OrganizationName xml:lang="da">Danmarks Tekniske Universitet</md:OrganizationName>
    <md:OrganizationName xml:lang="en">Technical University of Denmark</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="da">Danmarks Tekniske Universitet</md:OrganizationDisplayName>
    <md:OrganizationDisplayName xml:lang="en">Technical University of Denmark</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="da">http://www.dtu.dk</md:OrganizationURL>
    <md:OrganizationURL xml:lang="en">http://www.dtu.dk/English.aspx</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" contactType="technical">
    <md:EmailAddress>mailto:afos@adm.dtu.dk</md:EmailAddress>
  </md:ContactPerson>
  <md:ContactPerson xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:remd="http://refeds.org/metadata" contactType="other" remd:contactType="http://refeds.org/metadata/contactType/security">
    <md:GivenName>Morten</md:GivenName>
    <md:SurName>Als</md:SurName>
    <md:EmailAddress>mailto:mals@dtu.dk</md:EmailAddress>
    <md:TelephoneNumber>+4540804661</md:TelephoneNumber>
  </md:ContactPerson>
</md:EntityDescriptor>`)

idp_md_birk = goxml.NewXp(`<?xml version="1.0"?>
<md:EntityDescriptor xmlns:wayf="http://wayf.dk/2014/08/wayf" xmlns:remd="http://refeds.org/metadata" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://birk.wayf.dk/birk.php/wayf.ait.dtu.dk/saml2/idp/metadata.php">
  <md:Extensions>
    <mdattr:EntityAttributes>
      <saml:Attribute Name="http://macedir.org/entity-category-support" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" Name="urn:oasis:names:tc:SAML:attribute:assurance-certification">
        <saml:AttributeValue>https://refeds.org/sirtfi</saml:AttributeValue>
      </saml:Attribute>
    </mdattr:EntityAttributes>
    <mdrpi:RegistrationInfo registrationInstant="2012-02-03T13:34:44Z" registrationAuthority="https://www.wayf.dk">
      <mdrpi:RegistrationPolicy xml:lang="en">http://wayf.dk/images/stories/WAYF-filer/metadataregistrationpracticestatementwayf.pdf</mdrpi:RegistrationPolicy>
    </mdrpi:RegistrationInfo>
  </md:Extensions>
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:Extensions>
      <shibmd:Scope regexp="false">dtu.dk</shibmd:Scope>
      <mdui:UIInfo>
        <mdui:DisplayName xml:lang="da">Danmarks Tekniske Universitet</mdui:DisplayName>
        <mdui:DisplayName xml:lang="en">Technical University of Denmark</mdui:DisplayName>
        <mdui:Logo width="73" height="100">data:image/png;base64,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</mdui:Logo>
      </mdui:UIInfo>
      <mdui:DiscoHints>
        <mdui:DomainHint>dtu.dk</mdui:DomainHint>
      </mdui:DiscoHints>
    </md:Extensions>
    <md:KeyDescriptor>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIICtjCCAZ4CAQcwDQYJKoZIhvcNAQELBQAwITEfMB0GA1UEAwwWaHR0cHM6Ly93
YXlmc3Aud2F5Zi5kazAeFw0xNTAxMDEwMDAwMDBaFw0yNTEyMzEyMzU5NTlaMCEx
HzAdBgNVBAMMFmh0dHBzOi8vd2F5ZnNwLndheWYuZGswggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCfa+CetxGFykkAtZT0lRfspF6vIiRt7nd1MksUflqK
sRY0wxzqqNs8uuP8oJN09CuTUY+ysrifHWee5LY7FpCzjjBefdVtlHaPCo11jLvM
PlaL1avNdbc2DBcUjpqaEo3bY6SI112U7miIFX/KG8P+1pBRkoRI5SGuIVNODrtn
36VENzizGxCPyUj18lWks1reNFi49WLyCFFJcRmgjBlF2t8XdUgJi2Le/EJuHibp
eydQR8l3IWUIfZlfQy4QCFpuHSERh42Bj4RAnrP07xawzR23HHpyLQ/LMm3X77HS
JAxkzDy3wqDA3VXiOJrftsfD+ZY5kruloScX2Ck+ciHdAgMBAAEwDQYJKoZIhvcN
AQELBQADggEBAI5f9RoiSlarcKvIx/HnGeo6t98iUPXaX/tyt5i/t4aRP+Kyr9n9
pK4hKR+WZhzOMx/GAGjzq7LuyjtlKhfVRu81uRt+zdltXF1JvF8mrejT+elljwqq
tn1eeT44hLykzj0LI8OB6gWGkxC2r1t3oWBWGlrrfVu9yXRtAzNkc59MF1Qa006B
MEQA6+2Eslr4Fr86etnZgXPjOQHKSsN2TnrLb/XKFJsbVuMqe72rUInchpGUOi7F
FKVZwXtNoFJ0HGQqX6ZRPfTaWBN4IH6MHoxbvYDfkfTwMra2+2J/vBCypWZvbpWN
+I+5HyxXbemzwaKK7zonmrBZ9PDi+JUctko=
</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://birk.wayf.dk/birk.php/wayf.ait.dtu.dk/saml2/idp/SSOService.php"/>
  </md:IDPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="da">Danmarks Tekniske Universitet</md:OrganizationName>
    <md:OrganizationName xml:lang="en">Technical University of Denmark</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="da">Danmarks Tekniske Universitet</md:OrganizationDisplayName>
    <md:OrganizationDisplayName xml:lang="en">Technical University of Denmark</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="da">http://www.dtu.dk</md:OrganizationURL>
    <md:OrganizationURL xml:lang="en">http://www.dtu.dk/English.aspx</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="technical">
    <md:EmailAddress>mailto:afos@adm.dtu.dk</md:EmailAddress>
  </md:ContactPerson>
  <md:ContactPerson contactType="other" remd:contactType="http://refeds.org/metadata/contactType/security">
    <md:GivenName>Morten</md:GivenName>
    <md:SurName>Als</md:SurName>
    <md:EmailAddress>mailto:mals@dtu.dk</md:EmailAddress>
    <md:TelephoneNumber>+4540804661</md:TelephoneNumber>
  </md:ContactPerson>
  <md:ContactPerson contactType="technical">
    <md:GivenName>WAYF</md:GivenName>
    <md:SurName>Operations</md:SurName>
    <md:EmailAddress>operations@wayf.dk</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>`)


sp_md = goxml.NewXp(`<?xml version="1.0"?>
<md:EntityDescriptor xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" xmlns:wayf="http://wayf.dk/2014/08/wayf" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://wayfsp.wayf.dk" ID="WAYF000279">
  <md:Extensions xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
    <mdrpi:RegistrationInfo xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" registrationInstant="2011-01-19T09:25:59Z"/>
    <wayf:wayf xmlns:wayf="http://wayf.dk/2014/08/wayf">
      <wayf:active>yes</wayf:active>
      <wayf:AttributeNameFormat/>
      <wayf:certFingerprint>da39a3ee5e6b4b0d3255bfef95601890afd80709</wayf:certFingerprint>
      <wayf:eduGAIN/>
      <wayf:eid>279</wayf:eid>
      <wayf:env>prod</wayf:env>
      <wayf:federation>WAYF</wayf:federation>
      <wayf:federation>nemlog-in.dk</wayf:federation>
      <wayf:federation>qa.kmd.dk</wayf:federation>
      <wayf:icon>1324561724_logo.png</wayf:icon>
      <wayf:kalmar>0</wayf:kalmar>
      <wayf:modified>2017-05-24T13:36:07Z</wayf:modified>
      <wayf:redirect.sign/>
      <wayf:redirect.validate/>
      <wayf:revisionid>181</wayf:revisionid>
      <wayf:RegistrationInstant2>2011-01-19T09:25:59Z</wayf:RegistrationInstant2>
      <wayf:type>saml20-sp</wayf:type>
      <wayf:url xml:lang="da">http://www.wayf.dk</wayf:url>
      <wayf:url xml:lang="en">http://www.wayf.dk</wayf:url>
    </wayf:wayf>
  </md:Extensions>
  <md:SPSSODescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="false">
    <md:Extensions>
      <mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">
        <mdui:Description xml:lang="da">Form&#xE5;let er at give udviklere mulighed for at unders&#xF8;ge omfang og syntaktisk kvalitet af de oplysninger som en institution oversender hver gang en af dens brugere fors&#xF8;ger at logge ind p&#xE5; en webtjeneste via WAYF.</mdui:Description>
        <mdui:Description xml:lang="en">The purpose is to enable developers to inspect the extent and syntactical quality of the information sent from an institution every time one of its users attempts to log into a web service through WAYF.</mdui:Description>
        <mdui:DisplayName xml:lang="da">WAYF Testtjeneste</mdui:DisplayName>
        <mdui:DisplayName xml:lang="en">WAYF Testing Service</mdui:DisplayName>
      </mdui:UIInfo>
    </md:Extensions>
    <md:KeyDescriptor>
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIEZzCCA0+gAwIBAgILAQAAAAABID3xVZIwDQYJKoZIhvcNAQEFBQAwajEjMCEGA1UECxMaT3JnYW5pemF0aW9uIFZhbGlkYXRpb24gQ0ExEzARBgNVBAoTCkdsb2JhbFNpZ24xLjAsBgNVBAMTJUdsb2JhbFNpZ24gT3JnYW5pemF0aW9uIFZhbGlkYXRpb24gQ0EwHhcNMDkwMzI1MTMwNTE0WhcNMTIwNTA5MDcwNzU3WjCBgzELMAkGA1UEBhMCREsxETAPBgNVBAgTCE9kZW5zZSBNMREwDwYDVQQHEwhPZGVuc2UgTTEbMBkGA1UECxMSV0FZRiAtIFNlY3JldGFyaWF0MR0wGwYDVQQKExRTeWRkYW5zayBVbml2ZXJzaXRldDESMBAGA1UEAxQJKi53YXlmLmRrMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBsuiyO84OVwkKR0TL6w8viWV4jMg+Jy7LgiEtYfHdnVBCvdM9XJJetS0MiJtulBH4/4ZWrfeGeHgLPvSjp6FiRdI1nDg/33ofc0TdNytxX4tBCzvxM0C4yCCaEXda+tqXJmGua+mVubMhS8kizHjL+s7A8xUqXoEFqOMHtgqoAQIDAQABo4IBdjCCAXIwHwYDVR0jBBgwFoAUfW0q7Garp1E2qwJp8XCPxFkLmh8wSQYIKwYBBQUHAQEEPTA7MDkGCCsGAQUFBzAChi1odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24ubmV0L2NhY2VydC9vcmd2MS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC5nbG9iYWxzaWduLm5ldC9Pcmdhbml6YXRpb25WYWwxLmNybDAdBgNVHQ4EFgQUvlkjTc0iuzcvi752QgktLT01obgwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBaAwKQYDVR0lBCIwIAYIKwYBBQUHAwEGCCsGAQUFBwMCBgorBgEEAYI3CgMDMEsGA1UdIAREMEIwQAYJKwYBBAGgMgEUMDMwMQYIKwYBBQUHAgEWJWh0dHA6Ly93d3cuZ2xvYmFsc2lnbi5uZXQvcmVwb3NpdG9yeS8wEQYJYIZIAYb4QgEBBAQDAgbAMA0GCSqGSIb3DQEBBQUAA4IBAQCKPVJYHjKOrzWtjPBTEJOwIzE0wSIcA+9+GNR5Pvk+6OTf2QTUDDHpXiiIEcYPL1kN/BEvA+N2y+7qyI5MlL7DNIu9clx1lcqhXiQ0lWcu7Bmb7VNPKq5WS1W81GhbZrO6BJtsQctU6odDXMoORay7FxnaxGHOaJlCSQDgT7QrRhzyd80X8NxrSV25byCTb31du8xoO+WagnqAp6xbKs6IsESDw2r/i3rLOXbL37B7lnbjcLC963xN6j7+kiyqiCjvrP0GLfSV4/FN9i9hWrdMlcbnvr23yz5Jflc1oFPtJx7GZqtV0uTijGxCr+aRaUzBPqc3kyavHJcCsn5TcL1t</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://wayfsp.wayf.dk/ss/module.php/saml/sp/saml2-logout.php/default-sp"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" index="0" Location="https://wayfsp.wayf.dk/ss/module.php/saml/sp/saml2-acs.php/default-sp"/>
    <md:AttributeConsumingService index="1" isDefault="true">
      <md:ServiceName xml:lang="da">WAYF Testtjeneste</md:ServiceName>
      <md:ServiceName xml:lang="en">WAYF Testing Service</md:ServiceName>
      <md:ServiceDescription xml:lang="da">Form&#xE5;let er at give udviklere mulighed for at unders&#xF8;ge omfang og syntaktisk kvalitet af de oplysninger som en institution oversender hver gang en af dens brugere fors&#xF8;ger at logge ind p&#xE5; en webtjeneste via WAYF.</md:ServiceDescription>
      <md:ServiceDescription xml:lang="en">The purpose is to enable developers to inspect the extent and syntactical quality of the information sent from an institution every time one of its users attempts to log into a web service through WAYF.</md:ServiceDescription>
      <md:RequestedAttribute FriendlyName="cn" Name="urn:oid:2.5.4.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonAssurance" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.11" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonEntitlement" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrimaryAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrincipalName" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonScopedAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonTargetedID" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="gn" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="mail" Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="norEduPersonLIN" Name="urn:oid:1.3.6.1.4.1.2428.90.1.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="norEduPersonNIN" Name="urn:oid:1.3.6.1.4.1.2428.90.1.5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="organizationName" Name="urn:oid:2.5.4.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="preferredLanguage" Name="urn:oid:2.16.840.1.113730.3.1.39" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacCountryOfCitizenship" Name="urn:oid:1.3.6.1.4.1.25178.1.2.5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacDateOfBirth" Name="urn:oid:1.3.6.1.4.1.25178.1.2.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacHomeOrganization" Name="urn:oid:1.3.6.1.4.1.25178.1.2.9" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacPersonalUniqueID" Name="urn:oid:1.3.6.1.4.1.25178.1.2.15" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacYearOfBirth" Name="urn:oid:1.3.6.1.4.1.25178.1.0.2.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="sn" Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacHomeOrganizationType" Name="urn:oid:1.3.6.1.4.1.25178.1.2.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
  <md:ContactPerson xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" contactType="technical">
    <md:EmailAddress>mailto:benji@wayf.dk</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>`)

sp_md_krib = goxml.NewXp(`<?xml version="1.0"?>
<md:EntityDescriptor xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" xmlns:wayf="http://wayf.dk/2014/08/wayf" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://krib.wayf.dk/krib.php/wayfsp.wayf.dk" ID="KRIB-WAYF000279">
  <md:Extensions xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
    <mdrpi:RegistrationInfo xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" registrationInstant="2011-01-19T09:25:59Z" registrationAuthority="https://www.wayf.dk">
      <mdrpi:RegistrationPolicy xml:lang="en">http://wayf.dk/images/stories/WAYF-filer/metadataregistrationpracticestatementwayf.pdf</mdrpi:RegistrationPolicy>
    </mdrpi:RegistrationInfo>
    <wayf:wayf xmlns:wayf="http://wayf.dk/2014/08/wayf">
      <wayf:active>yes</wayf:active>
      <wayf:AttributeNameFormat/>
      <wayf:certFingerprint>da39a3ee5e6b4b0d3255bfef95601890afd80709</wayf:certFingerprint>
      <wayf:eduGAIN/>
      <wayf:eid>279</wayf:eid>
      <wayf:env>prod</wayf:env>
      <wayf:federation>WAYF</wayf:federation>
      <wayf:federation>nemlog-in.dk</wayf:federation>
      <wayf:federation>qa.kmd.dk</wayf:federation>
      <wayf:icon>1324561724_logo.png</wayf:icon>
      <wayf:kalmar>0</wayf:kalmar>
      <wayf:modified>2017-05-24T13:36:07Z</wayf:modified>
      <wayf:redirect.sign/>
      <wayf:redirect.validate/>
      <wayf:revisionid>181</wayf:revisionid>
      <wayf:RegistrationInstant2>2011-01-19T09:25:59Z</wayf:RegistrationInstant2>
      <wayf:type>saml20-sp</wayf:type>
      <wayf:url xml:lang="da">http://www.wayf.dk</wayf:url>
      <wayf:url xml:lang="en">http://www.wayf.dk</wayf:url>
    </wayf:wayf>
  </md:Extensions>
  <md:SPSSODescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="false">
    <md:Extensions>
      <mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">
        <mdui:Description xml:lang="da">Form&#xE5;let er at give udviklere mulighed for at unders&#xF8;ge omfang og syntaktisk kvalitet af de oplysninger som en institution oversender hver gang en af dens brugere fors&#xF8;ger at logge ind p&#xE5; en webtjeneste via WAYF.</mdui:Description>
        <mdui:Description xml:lang="en">The purpose is to enable developers to inspect the extent and syntactical quality of the information sent from an institution every time one of its users attempts to log into a web service through WAYF.</mdui:Description>
        <mdui:DisplayName xml:lang="da">WAYF Testtjeneste</mdui:DisplayName>
        <mdui:DisplayName xml:lang="en">WAYF Testing Service</mdui:DisplayName>
        <mdui:Logo width="300" height="128">data:image/png;base64,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</mdui:Logo>
      </mdui:UIInfo>
    </md:Extensions>
    <md:KeyDescriptor>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIICtjCCAZ4CAQcwDQYJKoZIhvcNAQELBQAwITEfMB0GA1UEAwwWaHR0cHM6Ly93
YXlmc3Aud2F5Zi5kazAeFw0xNTAxMDEwMDAwMDBaFw0yNTEyMzEyMzU5NTlaMCEx
HzAdBgNVBAMMFmh0dHBzOi8vd2F5ZnNwLndheWYuZGswggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCfa+CetxGFykkAtZT0lRfspF6vIiRt7nd1MksUflqK
sRY0wxzqqNs8uuP8oJN09CuTUY+ysrifHWee5LY7FpCzjjBefdVtlHaPCo11jLvM
PlaL1avNdbc2DBcUjpqaEo3bY6SI112U7miIFX/KG8P+1pBRkoRI5SGuIVNODrtn
36VENzizGxCPyUj18lWks1reNFi49WLyCFFJcRmgjBlF2t8XdUgJi2Le/EJuHibp
eydQR8l3IWUIfZlfQy4QCFpuHSERh42Bj4RAnrP07xawzR23HHpyLQ/LMm3X77HS
JAxkzDy3wqDA3VXiOJrftsfD+ZY5kruloScX2Ck+ciHdAgMBAAEwDQYJKoZIhvcN
AQELBQADggEBAI5f9RoiSlarcKvIx/HnGeo6t98iUPXaX/tyt5i/t4aRP+Kyr9n9
pK4hKR+WZhzOMx/GAGjzq7LuyjtlKhfVRu81uRt+zdltXF1JvF8mrejT+elljwqq
tn1eeT44hLykzj0LI8OB6gWGkxC2r1t3oWBWGlrrfVu9yXRtAzNkc59MF1Qa006B
MEQA6+2Eslr4Fr86etnZgXPjOQHKSsN2TnrLb/XKFJsbVuMqe72rUInchpGUOi7F
FKVZwXtNoFJ0HGQqX6ZRPfTaWBN4IH6MHoxbvYDfkfTwMra2+2J/vBCypWZvbpWN
+I+5HyxXbemzwaKK7zonmrBZ9PDi+JUctko=
</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" index="0" Location="https://krib.wayf.dk/krib.php/wayfsp.wayf.dk/ss/module.php/saml/sp/saml2-acs.php/default-sp"/>
    <md:AttributeConsumingService index="1" isDefault="true">
      <md:ServiceName xml:lang="da">WAYF Testtjeneste</md:ServiceName>
      <md:ServiceName xml:lang="en">WAYF Testing Service</md:ServiceName>
      <md:ServiceDescription xml:lang="da">Form&#xE5;let er at give udviklere mulighed for at unders&#xF8;ge omfang og syntaktisk kvalitet af de oplysninger som en institution oversender hver gang en af dens brugere fors&#xF8;ger at logge ind p&#xE5; en webtjeneste via WAYF.</md:ServiceDescription>
      <md:ServiceDescription xml:lang="en">The purpose is to enable developers to inspect the extent and syntactical quality of the information sent from an institution every time one of its users attempts to log into a web service through WAYF.</md:ServiceDescription>
      <md:RequestedAttribute FriendlyName="cn" Name="urn:oid:2.5.4.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonAssurance" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.11" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonEntitlement" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrimaryAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrincipalName" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonScopedAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonTargetedID" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="gn" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="mail" Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="norEduPersonLIN" Name="urn:oid:1.3.6.1.4.1.2428.90.1.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="norEduPersonNIN" Name="urn:oid:1.3.6.1.4.1.2428.90.1.5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="organizationName" Name="urn:oid:2.5.4.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="preferredLanguage" Name="urn:oid:2.16.840.1.113730.3.1.39" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacCountryOfCitizenship" Name="urn:oid:1.3.6.1.4.1.25178.1.2.5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacDateOfBirth" Name="urn:oid:1.3.6.1.4.1.25178.1.2.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacHomeOrganization" Name="urn:oid:1.3.6.1.4.1.25178.1.2.9" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacPersonalUniqueID" Name="urn:oid:1.3.6.1.4.1.25178.1.2.15" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacYearOfBirth" Name="urn:oid:1.3.6.1.4.1.25178.1.0.2.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="sn" Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacHomeOrganizationType" Name="urn:oid:1.3.6.1.4.1.25178.1.2.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
  <md:ContactPerson xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" contactType="technical">
    <md:EmailAddress>mailto:benji@wayf.dk</md:EmailAddress>
  </md:ContactPerson>
  <md:ContactPerson contactType="technical">
    <md:GivenName>WAYF</md:GivenName>
    <md:SurName>Operations</md:SurName>
    <md:EmailAddress>operations@wayf.dk</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>`)



hub_md = goxml.NewXp(`<?xml version="1.0"?>
<md:EntityDescriptor xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:wayf="http://wayf.dk/2014/08/wayf" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" entityID="https://wayf.wayf.dk" validUntil="2017-08-28T12:10:08Z" cacheDuration="PT6H" ID="_1e4f9a5876271b6ce042fa2354351e13863a6d3e"><ds:Signature>
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
     <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
     <ds:Reference URI="#_1e4f9a5876271b6ce042fa2354351e13863a6d3e">
       <ds:Transforms>
         <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
         <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
       </ds:Transforms>
       <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>zKJ0/t+h8nnzqlJzukWsEN7Y+J274C+CXtwWK7FDvqE=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>gwWJS+ygw45g5jjlaH/Ey1Woy1sVumHJkKTmNoxNf3v//SkyzblpqC/fQDP8gGWsvNdJhcX2IE5/4GX0tloXkR0MprP2jfSVeno+E04W5QYWE1M0orwK0ojx+KpImZEYCCAWipS+tY0Bwa5iKOtzQ4QTMgjI0l/3iik35/ZYe3D1+KyAn9uiVls3qSoP3gsd7eblRtYDcRqLdeUQZzbjO5gUhtMqrAeaWR9u5y3MaO3EUq7EQSFMVUdTNEq6k2cVUqnBZ/G6T/rsgkfg1Ut9GwBoUtBRmmcRo8wWT0rDrspdb6VmvtK82IWEAUde5NiUTqMCAKmWct6gfv3xYGPf3Q==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDNjCCAh4CCQDsE0eLyC+FjDANBgkqhkiG9w0BAQUFADCBiDELMAkGA1UEBhMC
REsxEDAOBgNVBAgTB0Rlbm1hcmsxEzARBgNVBAcUCkvDuGJlbmhhdm4xFzAVBgNV
BAoTDnRlc3QgV0FZRiB0ZXN0MRswGQYDVQQDExJ0ZXN0IFdBWUYgdGVzdC5sYW4x
HDAaBgkqhkiG9w0BCQEWDWZpbm5kQHdheWYuZGswHhcNMTUwNjEwMDc1NjEwWhcN
MjAwNTE0MDc1NjEwWjAxMQswCQYDVQQGEwJESzENMAsGA1UEChMEV0FZRjETMBEG
A1UEAxQKKi50ZXN0LmxhbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJ9r4J63EYXKSQC1lPSVF+ykXq8iJG3ud3UySxR+WoqxFjTDHOqo2zy64/ygk3T0
K5NRj7KyuJ8dZ57ktjsWkLOOMF591W2Udo8KjXWMu8w+VovVq811tzYMFxSOmpoS
jdtjpIjXXZTuaIgVf8obw/7WkFGShEjlIa4hU04Ou2ffpUQ3OLMbEI/JSPXyVaSz
Wt40WLj1YvIIUUlxGaCMGUXa3xd1SAmLYt78Qm4eJul7J1BHyXchZQh9mV9DLhAI
Wm4dIRGHjYGPhECes/TvFrDNHbccenItD8sybdfvsdIkDGTMPLfCoMDdVeI4mt+2
x8P5ljmSu6WhJxfYKT5yId0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAeVWElKLi
aIkX2SYpxoePn2Atxb/mKIV1ttm4hZLJWAhMwUk9xYRQCim9X1aO8OMpMI346omr
ED/wTbPjAC4wG0M0K/n+7GVC+xFbyup+N8D5P1fIlbB+hs/hQih1W3N7WAtcRCHc
kBhYOnUtNYZTgKbilXFLYIRRCmFNGN2vRU9KfYoQ19AYHuK5+vGVzeYqRFY6EJx0
ttXZVVH8Yc7FYjue6rheNaE4ZGOMSjVMoeqps7q6jqrbw1eMdhdFZnD7HzrRndpq
zjvT0OgSAWqrjznERRb5hu/2410d0N1nGqLOHfgSm5otnltg+/3WvuaqxTfMnkgL
/qJPaVd8ZDeWBg==
</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:Extensions><mdrpi:PublicationInfo xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" creationInstant="2017-08-21T12:10:08Z" publisher="http://www.wayf.dk"/></md:Extensions>

  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor>
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIDNjCCAh4CCQDsE0eLyC+FjDANBgkqhkiG9w0BAQUFADCBiDELMAkGA1UEBhMC
REsxEDAOBgNVBAgTB0Rlbm1hcmsxEzARBgNVBAcUCkvDuGJlbmhhdm4xFzAVBgNV
BAoTDnRlc3QgV0FZRiB0ZXN0MRswGQYDVQQDExJ0ZXN0IFdBWUYgdGVzdC5sYW4x
HDAaBgkqhkiG9w0BCQEWDWZpbm5kQHdheWYuZGswHhcNMTUwNjEwMDc1NjEwWhcN
MjAwNTE0MDc1NjEwWjAxMQswCQYDVQQGEwJESzENMAsGA1UEChMEV0FZRjETMBEG
A1UEAxQKKi50ZXN0LmxhbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJ9r4J63EYXKSQC1lPSVF+ykXq8iJG3ud3UySxR+WoqxFjTDHOqo2zy64/ygk3T0
K5NRj7KyuJ8dZ57ktjsWkLOOMF591W2Udo8KjXWMu8w+VovVq811tzYMFxSOmpoS
jdtjpIjXXZTuaIgVf8obw/7WkFGShEjlIa4hU04Ou2ffpUQ3OLMbEI/JSPXyVaSz
Wt40WLj1YvIIUUlxGaCMGUXa3xd1SAmLYt78Qm4eJul7J1BHyXchZQh9mV9DLhAI
Wm4dIRGHjYGPhECes/TvFrDNHbccenItD8sybdfvsdIkDGTMPLfCoMDdVeI4mt+2
x8P5ljmSu6WhJxfYKT5yId0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAeVWElKLi
aIkX2SYpxoePn2Atxb/mKIV1ttm4hZLJWAhMwUk9xYRQCim9X1aO8OMpMI346omr
ED/wTbPjAC4wG0M0K/n+7GVC+xFbyup+N8D5P1fIlbB+hs/hQih1W3N7WAtcRCHc
kBhYOnUtNYZTgKbilXFLYIRRCmFNGN2vRU9KfYoQ19AYHuK5+vGVzeYqRFY6EJx0
ttXZVVH8Yc7FYjue6rheNaE4ZGOMSjVMoeqps7q6jqrbw1eMdhdFZnD7HzrRndpq
zjvT0OgSAWqrjznERRb5hu/2410d0N1nGqLOHfgSm5otnltg+/3WvuaqxTfMnkgL
/qJPaVd8ZDeWBg==
</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://wayf.wayf.dk/module.php/saml/sp/saml2-logout.php/wayf.wayf.dk"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://wayf.wayf.dk/module.php/saml/sp/saml2-acs.php/wayf.wayf.dk" index="0"/>
    <md:AttributeConsumingService xmlns:wayf="http://wayf.dk/2014/08/wayf" index="0">
     <md:ServiceName xml:lang="da">WAYF - Where Are You From</md:ServiceName>
      <md:ServiceName xml:lang="en">WAYF - Where Are You From</md:ServiceName>
      <md:ServiceDescription xml:lang="da">WAYF - Where Are You From</md:ServiceDescription>
      <md:ServiceDescription xml:lang="en">WAYF - Where Are You From</md:ServiceDescription>
      <md:RequestedAttribute FriendlyName="sn" wayf:singular="true" wayf:must="true" Name="sn" isRequired="true" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="gn" wayf:singular="true" wayf:must="true" Name="gn" isRequired="true" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="cn" wayf:singular="true" wayf:must="true" Name="cn" isRequired="true" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrincipalName" wayf:singular="true" wayf:mandatory="true" Name="eduPersonPrincipalName" isRequired="true" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="mail" Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrimaryAffiliation" wayf:singular="true" wayf:must="true" Name="eduPersonPrimaryAffiliation" isRequired="true" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="organizationName" wayf:singular="true" wayf:must="true" Name="organizationName" isRequired="true" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="eduPersonAssurance" wayf:singular="true" wayf:must="true" Name="eduPersonAssurance" isRequired="true" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="schacPersonalUniqueID" Name="schacPersonalUniqueID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="schacCountryOfCitizenship" wayf:singular="true" Name="schacCountryOfCitizenship" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="eduPersonScopedAffiliation" Name="eduPersonScopedAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="preferredLanguage" Name="preferredLanguage" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="eduPersonEntitlement" Name="eduPersonEntitlement" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="norEduPersonLIN" Name="norEduPersonLIN" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="schacHomeOrganization" wayf:computed="true" Name="schacHomeOrganization" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="eduPersonTargetedID" wayf:computed="true" Name="eduPersonTargetedID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="schacDateOfBirth" Name="schacDateOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
	  <md:RequestedAttribute FriendlyName="schacYearOfBirth" Name="schacYearOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
	  <md:RequestedAttribute FriendlyName="schacHomeOrganizationType" wayf:computed="true" Name="schacHomeOrganizationType" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
	  <md:RequestedAttribute FriendlyName="eduPersonAffiliation" Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
      <md:RequestedAttribute FriendlyName="displayName" Name="displayName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:Extensions>
      <mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">
        <mdui:Description xml:lang="da">WAYF - den danske identitetsf&#xF8;deration for forskning og uddannelse</mdui:Description>
        <mdui:Description xml:lang="en">WAYF - The Danish identity federation for research and higher education</mdui:Description>
        <mdui:DisplayName xml:lang="da">WAYF - Where Are You From</mdui:DisplayName>
        <mdui:DisplayName xml:lang="en">WAYF - Where Are You From</mdui:DisplayName>
      </mdui:UIInfo>
    <shibmd:Scope regexp="false">adm.aau.dk@aau.dk</shibmd:Scope><shibmd:Scope regexp="false">aub.aau.dk@aau.dk</shibmd:Scope><shibmd:Scope regexp="false">civil.aau.dk@aau.dk</shibmd:Scope><shibmd:Scope regexp="false">create.aau.dk@aau.dk</shibmd:Scope><shibmd:Scope regexp="false">es.aau.dk@aau.dk</shibmd:Scope><shibmd:Scope regexp="false">hst.aau.dk@aau.dk</shibmd:Scope><shibmd:Scope regexp="false">id.aau.dk@aau.dk</shibmd:Scope><shibmd:Scope regexp="false">its.aau.dk@aau.dk</shibmd:Scope><shibmd:Scope regexp="false">learning.aau.dk@aau.dk</shibmd:Scope><shibmd:Scope regexp="false">m-tech.aau.dk@aau.dk</shibmd:Scope><shibmd:Scope regexp="false">plan.aau.dk@aau.dk</shibmd:Scope><shibmd:Scope regexp="false">sbi.aau.dk@aau.dk</shibmd:Scope><shibmd:Scope regexp="false">staff.aau.dk@aau.dk</shibmd:Scope><shibmd:Scope regexp="false">student.aau.dk@aau.dk</shibmd:Scope><shibmd:Scope regexp="false">kb.dk</shibmd:Scope><shibmd:Scope regexp="false">hi.is</shibmd:Scope><shibmd:Scope regexp="false">ruc.dk</shibmd:Scope><shibmd:Scope regexp="false">orphanage.wayf.dk</shibmd:Scope><shibmd:Scope regexp="false">ucl.dk</shibmd:Scope><shibmd:Scope regexp="false">aau.dk</shibmd:Scope><shibmd:Scope regexp="false">viauc.dk</shibmd:Scope><shibmd:Scope regexp="false">ucc.dk</shibmd:Scope><shibmd:Scope regexp="false">drlund-gym.dk</shibmd:Scope><shibmd:Scope regexp="false">sdu.dk</shibmd:Scope><shibmd:Scope regexp="false">itu.dk</shibmd:Scope><shibmd:Scope regexp="false">paderup-gym.dk</shibmd:Scope><shibmd:Scope regexp="false">grenaa-gym.dk</shibmd:Scope><shibmd:Scope regexp="false">marselisborg-gym.dk</shibmd:Scope><shibmd:Scope regexp="false">sosuaarhus.dk</shibmd:Scope><shibmd:Scope regexp="false">sss.itsf.dk</shibmd:Scope><shibmd:Scope regexp="false">its.itsf.dk</shibmd:Scope><shibmd:Scope regexp="false">sikker-adgang.dk</shibmd:Scope><shibmd:Scope regexp="false">ibc.dk</shibmd:Scope><shibmd:Scope regexp="false">rungsted-gym.dk</shibmd:Scope><shibmd:Scope regexp="false">ucsj.dk</shibmd:Scope><shibmd:Scope regexp="false">zbc.dk</shibmd:Scope><shibmd:Scope regexp="false">frsgym.dk</shibmd:Scope><shibmd:Scope regexp="false">cbs.dk</shibmd:Scope><shibmd:Scope regexp="false">ku.dk</shibmd:Scope><shibmd:Scope regexp="false">vordingborg-gym.dk</shibmd:Scope><shibmd:Scope regexp="false">dmjx.dk</shibmd:Scope><shibmd:Scope regexp="false">apoteket.dk</shibmd:Scope><shibmd:Scope regexp="false">erhvervsakademiaarhus.dk</shibmd:Scope><shibmd:Scope regexp="false">dtu.dk</shibmd:Scope><shibmd:Scope regexp="false">ucn.dk</shibmd:Scope><shibmd:Scope regexp="false">frhavn-gym.dk</shibmd:Scope><shibmd:Scope regexp="false">sde.dk</shibmd:Scope><shibmd:Scope regexp="false">eal.dk</shibmd:Scope><shibmd:Scope regexp="false">hrs.dk</shibmd:Scope><shibmd:Scope regexp="false">au.dk</shibmd:Scope><shibmd:Scope regexp="false">knord.dk</shibmd:Scope><shibmd:Scope regexp="false">eucnord.dk</shibmd:Scope><shibmd:Scope regexp="false">handelsskolen.com</shibmd:Scope><shibmd:Scope regexp="false">cphbusiness.dk</shibmd:Scope><shibmd:Scope regexp="false">eadania.dk</shibmd:Scope><shibmd:Scope regexp="false">dansidp-test.stads.dk</shibmd:Scope><shibmd:Scope regexp="false">dansidp-qa.stads.dk</shibmd:Scope><shibmd:Scope regexp="false">dansidp.stads.dk</shibmd:Scope><shibmd:Scope regexp="false">umit.dk</shibmd:Scope><shibmd:Scope regexp="false">rosborg-gym.dk</shibmd:Scope><shibmd:Scope regexp="false">basyd.dk</shibmd:Scope><shibmd:Scope regexp="false">statsbiblioteket.dk</shibmd:Scope><shibmd:Scope regexp="false">eamv.dk</shibmd:Scope><shibmd:Scope regexp="false">aams.dk</shibmd:Scope><shibmd:Scope regexp="false">regionsjaelland.dk</shibmd:Scope><shibmd:Scope regexp="false">dskd.dk</shibmd:Scope><shibmd:Scope regexp="false">fms.dk</shibmd:Scope><shibmd:Scope regexp="false">smk.dk</shibmd:Scope><shibmd:Scope regexp="false">msk.dk</shibmd:Scope><shibmd:Scope regexp="false">drcmr.dk</shibmd:Scope><shibmd:Scope regexp="false">simac.dk</shibmd:Scope><shibmd:Scope regexp="false">ucsyd.dk</shibmd:Scope><shibmd:Scope regexp="false">kmduni.dans.kmd.dk</shibmd:Scope><shibmd:Scope regexp="false">this.is.not.a.valid.idp</shibmd:Scope><shibmd:Scope regexp="false">nybuni.dans.kmd.dk</shibmd:Scope><shibmd:Scope regexp="false">peduni.dans.kmd</shibmd:Scope><shibmd:Scope regexp="false">dansidp-udv.stads.dk</shibmd:Scope><shibmd:Scope regexp="false">dansidp-test2.stads.dk</shibmd:Scope><shibmd:Scope regexp="false">oess.dk</shibmd:Scope><shibmd:Scope regexp="false">kadk.dk</shibmd:Scope><shibmd:Scope regexp="false">musikkons.dk</shibmd:Scope><shibmd:Scope regexp="false">easj.dk</shibmd:Scope><shibmd:Scope regexp="false">easv.dk</shibmd:Scope><shibmd:Scope regexp="false">dsl.dk</shibmd:Scope><shibmd:Scope regexp="false">phmetropol.dk</shibmd:Scope><shibmd:Scope regexp="false">rm.dk</shibmd:Scope><shibmd:Scope regexp="false">fak.dk</shibmd:Scope><shibmd:Scope regexp="false">pha.dk</shibmd:Scope><shibmd:Scope regexp="false">kea.dk</shibmd:Scope></md:Extensions>
    <md:KeyDescriptor>
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIDNjCCAh4CCQDsE0eLyC+FjDANBgkqhkiG9w0BAQUFADCBiDELMAkGA1UEBhMC
REsxEDAOBgNVBAgTB0Rlbm1hcmsxEzARBgNVBAcUCkvDuGJlbmhhdm4xFzAVBgNV
BAoTDnRlc3QgV0FZRiB0ZXN0MRswGQYDVQQDExJ0ZXN0IFdBWUYgdGVzdC5sYW4x
HDAaBgkqhkiG9w0BCQEWDWZpbm5kQHdheWYuZGswHhcNMTUwNjEwMDc1NjEwWhcN
MjAwNTE0MDc1NjEwWjAxMQswCQYDVQQGEwJESzENMAsGA1UEChMEV0FZRjETMBEG
A1UEAxQKKi50ZXN0LmxhbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJ9r4J63EYXKSQC1lPSVF+ykXq8iJG3ud3UySxR+WoqxFjTDHOqo2zy64/ygk3T0
K5NRj7KyuJ8dZ57ktjsWkLOOMF591W2Udo8KjXWMu8w+VovVq811tzYMFxSOmpoS
jdtjpIjXXZTuaIgVf8obw/7WkFGShEjlIa4hU04Ou2ffpUQ3OLMbEI/JSPXyVaSz
Wt40WLj1YvIIUUlxGaCMGUXa3xd1SAmLYt78Qm4eJul7J1BHyXchZQh9mV9DLhAI
Wm4dIRGHjYGPhECes/TvFrDNHbccenItD8sybdfvsdIkDGTMPLfCoMDdVeI4mt+2
x8P5ljmSu6WhJxfYKT5yId0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAeVWElKLi
aIkX2SYpxoePn2Atxb/mKIV1ttm4hZLJWAhMwUk9xYRQCim9X1aO8OMpMI346omr
ED/wTbPjAC4wG0M0K/n+7GVC+xFbyup+N8D5P1fIlbB+hs/hQih1W3N7WAtcRCHc
kBhYOnUtNYZTgKbilXFLYIRRCmFNGN2vRU9KfYoQ19AYHuK5+vGVzeYqRFY6EJx0
ttXZVVH8Yc7FYjue6rheNaE4ZGOMSjVMoeqps7q6jqrbw1eMdhdFZnD7HzrRndpq
zjvT0OgSAWqrjznERRb5hu/2410d0N1nGqLOHfgSm5otnltg+/3WvuaqxTfMnkgL
/qJPaVd8ZDeWBg==
</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://wayf.wayf.dk/saml2/idp/SingleLogoutService.php"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://wayf.wayf.dk/saml2/idp/SSOService2.php"/>
  </md:IDPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">WAYF - Where Are You From</md:OrganizationName>
    <md:OrganizationName xml:lang="da">WAYF - Where Are You From</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">WAYF - Where Are You From</md:OrganizationDisplayName>
    <md:OrganizationDisplayName xml:lang="da">WAYF - Where Are You From</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="da">http://wayf.dk/index.php/da</md:OrganizationURL>
    <md:OrganizationURL xml:lang="en">http://wayf.dk/index.php/en</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="technical">
    <md:GivenName>WAYF</md:GivenName>
    <md:SurName>Operations</md:SurName>
    <md:EmailAddress>operations@wayf.dk</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>`)

)

func (m md) MDQ(key string) (xp *goxml.Xp, err error) {
    xp = m.entities[key]
    if xp == nil {
        err = fmt.Errorf("Not found: " + key)
    }
    return
}

func main() {
	//	logwriter, e := syslog.New(syslog.LOG_NOTICE, "goeleven")
	//	if e == nil {
	//		log.SetOutput(logwriter)
	//	}

	/*
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		signal.Notify(c, syscall.SIGTERM)
		go func() {
			<-c
			f, err := os.Create("hybrid.pprof")
			if err != nil {
				log.Fatal(err)
			}
			pprof.WriteHeapProfile(f)
			f.Close()
			os.Exit(1)
		}()

	*/

	/*
	   lMDQ_PATH="test_hub.mddb" lMDQ_URL="https://test-phph.test.lan/test-md/wayf-metadata.xml" lMDQ_HASH="e0cff78934baa85a4a1b084dcb586fe6bb2f7619" ./lMDQ
	   lMDQ_PATH="test_hub_ops.mddb" lMDQ_URL="https://phph.wayf.dk/test-md/HUB.xml" lMDQ_HASH="e0cff78934baa85a4a1b084dcb586fe6bb2f7619" ./lMDQ
	   lMDQ_PATH="test_edugain.mddb" lMDQ_URL="https://test-phph.test.lan/test-md/WAYF-INTERFED.xml" lMDQ_HASH="e0cff78934baa85a4a1b084dcb586fe6bb2f7619" ./lMDQ
	*/
	var err error
/*
	if hub, err = lMDQ.Open("/tmp/test_hub.mddb"); err != nil {
		log.Println(err)
	}
	if hub_ops, err = lMDQ.Open("/tmp/test_hybrid_fed.mddb"); err != nil {
		log.Println(err)
	}
	if edugain, err = lMDQ.Open("/tmp/test_hybrid_interfed.mddb"); err != nil {
		log.Println(err)
	}
*/

    hub = md{entities: make(map[string]*goxml.Xp)}
    hub.entities["https://wayf.wayf.dk"] = hub_md
    hub.entities["https://wayf.wayf.dk/saml2/idp/SSOService2.php"] = hub_md
    hub.entities["https://wayf.wayf.dk/module.php/saml/sp/saml2-acs.php/wayf.wayf.dk"] = hub_md

	hubmd, _ = hub.MDQ(config["HYBRID_HUB"])

	hub_ops = md{entities: make(map[string]*goxml.Xp)}
    hub_ops.entities["https://wayf.ait.dtu.dk/saml2/idp/metadata.php"] = idp_md
    hub_ops.entities["https://wayfsp.wayf.dk"] = sp_md
    hub_ops.entities["https://wayfsp.wayf.dk/ss/module.php/saml/sp/saml2-acs.php/default-sp"] = sp_md

	edugain = md{entities: make(map[string]*goxml.Xp)}
	edugain.entities["https://krib.wayf.dk/krib.php/wayfsp.wayf.dk"] = sp_md_krib
    edugain.entities["https://krib.wayf.dk/krib.php/wayfsp.wayf.dk/ss/module.php/saml/sp/saml2-acs.php/default-sp"] = sp_md_krib
    edugain.entities["https://birk.wayf.dk/birk.php/wayf.ait.dtu.dk/saml2/idp/metadata.php"] = idp_md_birk
    edugain.entities["https://birk.wayf.dk/birk.php/wayf.ait.dtu.dk/saml2/idp/SSOService.php"] = idp_md_birk

	attrs := goxml.NewXp(Wayfrequestedattributes)
	for _, attr := range attrs.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute") {
		friendlyName, _ := attr.(types.Element).GetAttribute("FriendlyName")
		name, _ := attr.(types.Element).GetAttribute("Name")
		basic2uri[friendlyName.NodeValue()] = name.NodeValue()
	}

	//http.HandleFunc("/status", statushandler)
	http.Handle(config["HYBRID_PUBLIC_PREFIX"], http.FileServer(http.Dir(config["HYBRID_PUBLIC"])))
	http.Handle(config["HYBRID_SSO_SERVICE"], appHandler(ssoService))
	http.Handle(config["HYBRID_ACS"], appHandler(acsService))
	http.Handle(config["HYBRID_BIRK"], appHandler(birkService))
	http.Handle(config["HYBRID_KRIB"], appHandler(kribService))
	http.Handle(config["WAYFSP_SP"], appHandler(wayfspService))
	http.Handle(config["WAYFSP_ACS"], appHandler(wayfspACService))

	log.Println("listening on ", config["HYBRID_INTERFACE"])
	err = http.ListenAndServeTLS(config["HYBRID_INTERFACE"], config["HYBRID_HTTPS_CERT"], config["HYBRID_HTTPS_KEY"], nil)
	//err = openssl.ListenAndServeTLS(config["HYBRID_INTERFACE"], config["HYBRID_HTTPS_CERT"], config["HYBRID_HTTPS_KEY"], nil)

	if err != nil {
		log.Printf("main(): %s\n", err)
	}
}

func wayfspService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	sp_md, _ := hub_ops.MDQ("https://wayfsp.wayf.dk")
	hub_Md, _ := hub.MDQ("https://wayf.wayf.dk")
	newrequest := gosaml.NewAuthnRequest(stdtiming.Refresh(), sp_md, hub_Md)
	u, _ := gosaml.SAMLRequest2Url(newrequest, "", "", "") // not signed so blank key, pw and algo
	u.Host = "wayf.wayf.dk"
	http.Redirect(w, r, u.String(), http.StatusFound)
	return
}

func wayfspACService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	response, _, _, err := gosaml.ReceiveSAMLResponse(r, hub, hub_ops)
	if err != nil {
	    log.Println(err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8") // normal header
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response.Doc.Dump(true)))
	log.Println(response.Doc.Dump(true))
	return
}

func ssoService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	// handle non ok urls gracefully
	// var err error
	// check issuer and acs in md
	// receiveRequest -> request, issuer md, receiver md
	//     check for IDPList 1st in md, then in request then in query
	//     sanitize idp from query or request
	request, spmd, _, err := gosaml.ReceiveSAMLRequest(r, hub_ops, hub)
	if err != nil {
		return
	}
	entityID := spmd.Query1(nil, "@entityID")
	idp := spmd.Query1(nil, "//IDPList/ProviderID") // Need to find a place for IDPList
	if idp == "" {
		idp = request.Query1(nil, "IDPList/ProviderID")
	}
	if idp == "" {
		idp = r.URL.Query().Get("idpentityid")
	}
	if idp == "" {
		data := url.Values{}
		data.Set("return", "https://"+r.Host+r.RequestURI)
		data.Set("returnIDParam", "idpentityid")
		data.Set("entityID", entityID)
		http.Redirect(w, r, config["HYBRID_DISCOVERY"]+data.Encode(), http.StatusFound)
	} else {
		var idpmd *goxml.Xp
		/**/
		// check overlap btw ad-hoc feds for the idp and the sp
		kribID := bify.ReplaceAllString(entityID, "${1}krib.wayf.dk/krib.php/$2")
		if kribID == entityID {
			kribID = "urn:oid:1.3.6.1.4.1.39153:42:" + entityID
		}

		request.QueryDashP(nil, "/saml:Issuer", kribID, nil)
		acs := request.Query1(nil, "@AssertionConsumerServiceURL")
		acsurl := bify.ReplaceAllString(acs, "${1}krib.wayf.dk/krib.php/$2")
		request.QueryDashP(nil, "@AssertionConsumerServiceURL", acsurl, nil)
		/**/
		idpmd, err = edugain.MDQ(idp)
		if err != nil {
			return
		}
		const ssoquery = "./md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location"
		ssoservice := idpmd.Query1(nil, ssoquery)
		if ssoservice == "" {

		}
		request.QueryDashP(nil, "@Destination", ssoservice, nil)
		u, _ := gosaml.SAMLRequest2Url(request, "", "", "")
		log.Println(request.Doc.Dump(true))
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	return
}

func birkService(w http.ResponseWriter, r *http.Request) (err error) {
    // use incoming request for crafting the new one
    // remember to add the Scoping element to inform the IdP of requesterID - if stated in metadata for the IdP
	defer r.Body.Close()
	// get the sp as well to check for allowed acs
	request, _, mdbirkidp, err := gosaml.ReceiveSAMLRequest(r, edugain, edugain)
	if err != nil {
		return
	}
	// Save the issuer and destination in a cookie for when the response comes back

	cookievalue := base64.StdEncoding.EncodeToString(gosaml.Deflate(request.Doc.Dump(true)))
	http.SetCookie(w, &http.Cookie{Name: "BIRK", Value: cookievalue, Domain: config["HYBRID_DOMAIN"], Path: "/", Secure: true, HttpOnly: true})

	idp := debify.ReplaceAllString(mdbirkidp.Query1(nil, "@entityID"), "$1$2")

	var mdhub, mdidp *goxml.Xp
	// are we remapping - for now only use case is https://nemlogin.wayf.dk -> https://saml.nemlog-in.dk
	if rm, ok := remap[idp]; ok {
		mdidp, err = hub_ops.MDQ(rm.idp)
		mdhub, err = hub_ops.MDQ(rm.sp)
	} else {
		mdidp, err = hub_ops.MDQ(idp)
		mdhub, err = hub.MDQ(config["HYBRID_HUB"])
	}
	// use a std request - we take care of NameID etc in acsService below
	newrequest := gosaml.NewAuthnRequest(stdtiming.Refresh(), mdhub, mdidp)
	// to-do delete the following line when md for the hub is OK
	newrequest.QueryDashP(nil, "@AssertionConsumerServiceURL", config["HYBRID_HUB"]+config["HYBRID_ACS"], nil)
	u, _ := gosaml.SAMLRequest2Url(newrequest, "", "", "") // not signed so blank key, pw and algo
	http.Redirect(w, r, u.String(), http.StatusFound)
	return
}

func acsService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	birk, err := r.Cookie("BIRK")
	if err != nil {
		return err
	}
	// to-do: check hmac
	// we checked the request when we received in birkService - we can use it without fear ie. we just parse it
	bmsg, err := base64.StdEncoding.DecodeString(birk.Value)
	log.Println("cookie", string(gosaml.Inflate(bmsg)))
    request:= goxml.NewXp(string(gosaml.Inflate(bmsg)))

	http.SetCookie(w, &http.Cookie{Name: "BIRK", Value: "", Domain: config["HYBRID_DOMAIN"], Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
	sp_md, err := edugain.MDQ(request.Query1(nil, "/samlp:AuthnRequest/saml:Issuer"))
	if err != nil {
	    return
	}

	response, idp_md, _, err := gosaml.ReceiveSAMLResponse(r, hub_ops, hub)
	if err != nil {
		return
	}

	// get issuer - if https://saml.nemlog-in.dk do nemlog-in handling before std. handling ie. decrypt and prepare attributes
	/*
	   map:
	   			'urn:oid:2.5.4.3' => 'cn',
	   			'urn:oid:0.9.2342.19200300.100.1.1' => 'eduPersonPrincipalName',
	   			'urn:oid:0.9.2342.19200300.100.1.3' => 'mail',
	   			'dk:gov:saml:attribute:AssuranceLevel' => 'eduPersonAssurance',
	   			'dk:gov:saml:attribute:CprNumberIdentifier' => 'schacPersonalUniqueID',
	   add:		'eduPersonPrimaryAffiliation' => 'member',
	   			'schacHomeOrganization' => 'http://sikker-adgang.dk',
	   			'organizationName' => 'NemLogin'
	   split       cn into gn and sn # 'urn:oid:2.5.4.3'
	   postfix     eduPersonPrincipalName with '@sikker-adgang.dk'
	   prefix      schacPersonalUniqueID with 'urn:mace:terena.org:schac:personalUniqueID:dk:CPR:'
	*/

	hub_md := goxml.NewXp(Wayfrequestedattributes)
	err = WayfAttributeHandler(idp_md, hub_md, sp_md, response)
	if err != nil {
		return
	}

	birkmd, err := edugain.MDQ(request.Query1(nil, "/samlp:AuthnRequest/@Destination"))
	if err != nil {
	    return
	}
	nameid := response.Query(nil, "./saml:Assertion/saml:Subject/saml:NameID")[0]
	// respect nameID in req, give persistent id + all computed attributes + nameformat conversion
	nameidformat := sp_md.Query1(nil, "./md:SPSSODescriptor/md:NameIDFormat")
	if nameidformat == persistent {
		response.QueryDashP(nameid, "@Format", persistent, nil)
		eptid := response.Query1(nil, `./saml:Assertion/saml:AttributeStatement/saml:Attribute[@FriendlyName="eduPersonTargetedID"]/saml:AttributeValue`)
		response.QueryDashP(nameid, ".", eptid, nil)
	} else if nameidformat == transient {
		response.QueryDashP(nameid, ".", gosaml.Id(), nil)
	}

	newresponse := gosaml.NewResponse(stdtiming.Refresh(), birkmd, sp_md, request, response)

	for _, q := range elementsToSign {
		err = gosaml.SignResponse(newresponse, q, birkmd)
		if err != nil {
			return
		}
	}

	// when consent as a service is ready - we will post to that
	acs := newresponse.Query1(nil, "@Destination")

	data := formdata{Acs: acs, Samlresponse: base64.StdEncoding.EncodeToString([]byte(newresponse.Doc.Dump(false)))}
	postform.Execute(w, data)
	return
}

func kribService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()

	response, _, _, err := gosaml.ReceiveSAMLResponse(r, edugain, edugain)
	if err != nil {
		return
	}
	destination := debify.ReplaceAllString(response.Query1(nil, "@Destination"), "$1$2")
	response.QueryDashP(nil, "@Destination", destination, nil)
	response.QueryDashP(nil, "./saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient", destination, nil)
	issuer := config["HYBRID_HUB"]
	response.QueryDashP(nil, "./saml:Issuer", issuer, nil)
	response.QueryDashP(nil, "./saml:Assertion/saml:Issuer", issuer, nil)
	// Krib always receives attributes with nameformat=urn. Before sending to the real SP we need to look into
	// the metadata for SP to determine the actual nameformat - as WAYF supports both for internal SPs.
	mdsp, err := hub_ops.MDQ(destination)
	if err != nil {
		return
	}
	requestedattributes := mdsp.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute")
	attributestatement := response.Query(nil, "./saml:Assertion/saml:AttributeStatement")[0]
	for _, attr := range requestedattributes {
		nameFormat, _ := attr.(types.Element).GetAttribute("NameFormat")
		if nameFormat.NodeValue() == basic {
			basicname, _ := attr.(types.Element).GetAttribute("Name")
			uriname := basic2uri[basicname.NodeValue()]
			responseattribute := response.Query(attributestatement, "saml:Attribute[@Name='"+uriname+"']")
			if len(responseattribute) > 0 {
				responseattribute[0].(types.Element).SetAttribute("Name", basicname.NodeValue())
				responseattribute[0].(types.Element).SetAttribute("NameFormat", basic)
			}
		}
	}

	mdhub, err := hub.MDQ(config["HYBRID_HUB"])
	if err != nil {
		return
	}

	for _, q := range elementsToSign {
		err = gosaml.SignResponse(response, q, mdhub)
		if err != nil {
			return
		}
	}

	data := formdata{Acs: destination, Samlresponse: base64.StdEncoding.EncodeToString([]byte(response.Doc.Dump(false)))}
	postform.Execute(w, data)
	return
}

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	/*	ctx := make(map[string]string)
		contextmutex.Lock()
		context[r] = ctx
		contextmutex.Unlock()
		w.Header().Set("content-Security-Policy", "referrer no-referrer;")
	*/
	starttime := time.Now()
	err := fn(w, r)

	status := 200
	if err != nil {
		status = 500
		http.Error(w, err.Error(), status)
	} else {
		err = fmt.Errorf("OK")
	}

	log.Printf("%s %s %s %+v %1.3f %d %s", r.RemoteAddr, r.Method, r.Host, r.URL, time.Since(starttime).Seconds(), status, err)

	/*	contextmutex.Lock()
		delete(context, r)
		contextmutex.Unlock()
	*/
}

func WayfAttributeHandler(idp_md, hub_md, sp_md, response *goxml.Xp) (err error) {
	sourceAttributes := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement`)[0]
	idp := response.Query1(nil, "/samlp:Response/saml:Issuer")
	base64encoded := idp_md.Query1(nil, "//wayf:base64attributes") == "1"

	attCS := hub_md.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService")[0]

	// First check for mandatory and multiplicity
	requestedAttributes := hub_md.Query(attCS, `md:RequestedAttribute[not(@computed)]`) // [@isRequired='true' or @isRequired='1']`)
	for _, requestedAttribute := range requestedAttributes {
		name, _ := requestedAttribute.(types.Element).GetAttribute("Name")
		friendlyName, _ := requestedAttribute.(types.Element).GetAttribute("FriendlyName")
		//nameFormat := requestedAttribute.GetAttr("NameFormat")
		mandatory := hub_md.QueryBool(requestedAttribute.(types.Element), "@mandatory")
		//must := hub_md.QueryBool(requestedAttribute, "@must")
		singular := hub_md.QueryBool(requestedAttribute.(types.Element), "@singular")

		// accept attributes in both uri and basic format
		attributes := response.Query(sourceAttributes, `saml:Attribute[@Name="`+name.NodeValue()+`" or @Name="`+friendlyName.NodeValue()+`"]`)
		if len(attributes) == 0 && mandatory {
			err = fmt.Errorf("mandatory: %s", friendlyName.NodeValue())
			return
		}
		for _, attribute := range attributes {
			valueNodes := response.Query(attribute, `saml:AttributeValue`)
			if len(valueNodes) > 1 && singular {
				err = fmt.Errorf("multiple values for singular attribute: %s", name.NodeValue())
				return
			}
			if len(valueNodes) != 1 && mandatory {
				err = fmt.Errorf("mandatory: %s", friendlyName.NodeValue())
				return
			}
			attribute.(types.Element).SetAttribute("Name", name.NodeValue())
			attribute.(types.Element).SetAttribute("FriendlyName", friendlyName.NodeValue())
			attribute.(types.Element).SetAttribute("NameFormat", uri)
			if base64encoded {
				for _, valueNode := range valueNodes {
					decoded, _ := base64.StdEncoding.DecodeString(valueNode.NodeValue())
					valueNode.SetNodeValue(string(decoded))
				}
			}
		}
	}

	// check that the security domain of eppn is one of the domains in the shib:scope list
	// we just check that everything after the (leftmost|rightmost) @ is in the scope list and save the value for later
	eppn := response.Query1(sourceAttributes, "saml:Attribute[@Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.6']/saml:AttributeValue")
	eppnregexp := regexp.MustCompile(`^[^\@]+\@([a-zA-Z0-9\.-]+)$`)
	matches := eppnregexp.FindStringSubmatch(eppn)
	if len(matches) != 2 {
		err = fmt.Errorf("eppn does not seem to be an eppn: %s", eppn)
		return
	}

	securitydomain := matches[1]

	scope := idp_md.Query(nil, "//shibmd:Scope[.='"+securitydomain+"']")
	if len(scope) == 0 {
		err = fmt.Errorf("security domain '%s' for eppn does not match any scopes", securitydomain)
	}

	val := idp_md.Query1(nil, "./md:Extensions/wayf:wayf/wayf:wayf_schacHomeOrganizationType")
	gosaml.CpAndSet(sourceAttributes.(types.Element), response, hub_md, attCS.(types.Element), "schacHomeOrganizationType", val)

	val = idp_md.Query1(nil, "./md:Extensions/wayf:wayf/wayf:wayf_schacHomeOrganization")
	gosaml.CpAndSet(sourceAttributes.(types.Element), response, hub_md, attCS.(types.Element), "schacHomeOrganization", val)

	if response.Query1(sourceAttributes, `saml:Attribute[@FriendlyName="displayName"]/saml:AttributeValue`) == "" {
		if cn := response.Query1(sourceAttributes, `saml:Attribute[@FriendlyName="cn"]/saml:AttributeValue`); cn != "" {
			gosaml.CpAndSet(sourceAttributes.(types.Element), response, hub_md, attCS.(types.Element), "displayName", cn)
		}
	}

	salt := "6xfkhc7juin4vlbetmmc0eyxumelnoku"
	sp := sp_md.Query1(nil, "@entityID")

	uidhashbase := "uidhashbase" + salt
	uidhashbase += strconv.Itoa(len(idp)) + ":" + idp
	uidhashbase += strconv.Itoa(len(sp)) + ":" + sp
	uidhashbase += strconv.Itoa(len(eppn)) + ":" + eppn
	uidhashbase += salt
	eptid := "WAYF-DK-" + hex.EncodeToString(goxml.Hash(crypto.SHA1, uidhashbase))

	gosaml.CpAndSet(sourceAttributes.(types.Element), response, hub_md, attCS.(types.Element), "eduPersonTargetedID", eptid)

	dkcprpreg := regexp.MustCompile(`^urn:mace:terena.org:schac:personalUniqueID:dk:CPR:(\d\d)(\d\d)(\d\d)(\d)\d\d\d$`)
	for _, cprelement := range response.Query(sourceAttributes, `saml:Attribute[@FriendlyName="schacPersonalUniqueID"]`) {
		// schacPersonalUniqueID is multi - use the first DK cpr found
		cpr := strings.TrimSpace(cprelement.NodeValue())
		if matches := dkcprpreg.FindStringSubmatch(cpr); len(matches) > 0 {
			cpryear, _ := strconv.Atoi(matches[3])
			c7, _ := strconv.Atoi(matches[4])
			year := strconv.Itoa(yearfromyearandcifferseven(cpryear, c7))

			gosaml.CpAndSet(sourceAttributes.(types.Element), response, hub_md, attCS.(types.Element), "schacDateOfBirth", year+matches[2]+matches[1])
			gosaml.CpAndSet(sourceAttributes.(types.Element), response, hub_md, attCS.(types.Element), "schacYearOfBirth", year)
			break
		}
	}

	subsecuritydomain := "." + securitydomain
	epsas := make(map[string]bool)

	for _, epsa := range response.QueryMulti(sourceAttributes, `saml:Attribute[@FriendlyName="eduPersonScopedAffiliation"]/saml:AttributeValue`) {
		epsa = strings.TrimSpace(epsa)
		epsaparts := strings.SplitN(epsa, "@", 2)
		if len(epsaparts) != 2 {
			fmt.Errorf("eduPersonScopedAffiliation: %s does not end with a domain", epsa)
			return
		}
		if !strings.HasSuffix(epsaparts[1], subsecuritydomain) && epsaparts[1] != securitydomain {
			fmt.Printf("eduPersonScopedAffiliation: %s has not '%s' as a domain suffix", epsa, securitydomain)
			return
		}
		epsas[epsa] = true
	}

	// primaryaffiliation => affiliation
	epaAdd := []string{}
	eppa := response.Query1(sourceAttributes, `saml:Attribute[@FriendlyName="eduPersonPrimaryAffiliation"]`)
	eppa = strings.TrimSpace(eppa)
	epas := response.QueryMulti(sourceAttributes, `saml:Attribute[@FriendlyName="eduPersonAffiliation"]`)
	epaset := make(map[string]bool)
	for _, epa := range epas {
		epaset[strings.TrimSpace(epa)] = true
	}
	if !epaset[eppa] {
		epaAdd = append(epaAdd, eppa)
		epaset[eppa] = true
	}
	// 'student', 'faculty', 'staff', 'employee' => member
	if epaset["student"] || epaset["faculty"] || epaset["staff"] || epaset["employee"] {
		epaAdd = append(epaAdd, "member")
		epaset["member"] = true
	}
	newattribute, _ := hub_md.Query(attCS, `md:RequestedAttribute[@FriendlyName="eduPersonAffiliation"]`)[0].Copy()
	_ = sourceAttributes.AddChild(newattribute)
	for i, epa := range epaAdd {
		response.QueryDashP(newattribute, `saml:AttributeValue[`+strconv.Itoa(i+1)+`]`, epa, nil)
	}
	newattribute, _ = hub_md.Query(attCS, `md:RequestedAttribute[@FriendlyName="eduPersonScopedAffiliation"]`)[0].Copy()
	_ = sourceAttributes.AddChild(newattribute)
	i := 1
	for epa, _ := range epaset {
		if epsas[epa] {
			continue
		}
		response.QueryDashP(newattribute, `saml:AttributeValue[`+strconv.Itoa(i)+`]`, epa+"@"+securitydomain, nil)
		i += 1

	}
	return
	// legal affiliations 'student', 'faculty', 'staff', 'affiliate', 'alum', 'employee', 'library-walk-in', 'member'
	// affiliations => scopedaffiliations
}

// 2408586234
func yearfromyearandcifferseven(year, c7 int) int {

	cpr2year := map[int]map[int]int{
		3: {99: 1900},
		4: {36: 2000, 99: 1900},
		8: {57: 2000, 99: 1800},
		9: {36: 2000, 99: 1900},
	}

	for x7, years := range cpr2year {
		if c7 <= x7 {
			for y, century := range years {
				if year <= y {
					year += century
					return year
				}
			}
		}
	}
	return 0
}
