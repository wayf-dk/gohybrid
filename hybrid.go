/* Hybrid implements the WAYF hybrid architecture
   - support for RelayState
   - does not seem to work: incl. Capitalization content-security-policy: referrer no-referrer;
   - redo no-referer - current version does not work !!!
   - MDQ lookup by location also for hub md

*/
package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/lMDQ"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"
)

type (
	formdata struct {
		Acs          string
		Samlresponse string
	}
)

type appHandler func(http.ResponseWriter, *http.Request) error

const (
	postformtemplate = `<html>
<body onload="document.forms[0].submit()">
<form action="{{.Acs}}" method="POST">
<input type=hidden value="{{.Samlresponse}}" name=SAMLResponse />
<input type=submit value="Submit" />
</form>
</body>
</html>`
)

var (
	_ = log.Printf // For debugging; delete when done.
	_ = fmt.Printf

	config = map[string]string{
		"HYBRID_DOMAIN":        "wayf.dk",
		"HYBRID_HUB":           "https://wayf.wayf.dk",
		"HYBRID_DISCOVERY":     "/DS/ds.html?",
		"HYBRID_INTERFACE":     "0.0.0.0:443",
		"HYBRID_HTTPS_KEY":     "src/github.com/wayf-dk/gohybrid/key.pem",
		"HYBRID_HTTPS_CERT":    "src/github.com/wayf-dk/gohybrid/cert.pem",
		"HYBRID_PUBLIC":        "src/github.com/wayf-dk/gohybrid/public",
		"HYBRID_PUBLIC_PREFIX": "/DS/",
		"HYBRID_SSO_SERVICE":   "/saml2/idp/SSOService.php",
		"HYBRID_ACS":           "/module.php/saml/sp/saml2-acs.php/wayf.wayf.dk",
		"HYBRID_BIRK":          "/birk.php/",
		"HYBRID_KRIB":          "/krib.php/",
		"HYBRID_MDQ_HUB":       "https://test-phph.test.lan/MDQ/WAYF-HUB-PUBLIC",
		"HYBRID_MDQ_HUB_OPS":   "https://test-phph.test.lan/MDQ/HUB-OPS",
		"HYBRID_MDQ_EDUGAIN":   "https://test-phph.test.lan/MDQ/MEC",
		"HYBRID_MDQ_BIRK":      "https://test-phph.test.lan/MDQ/BIRK-OPS",
	}

	contextmutex sync.RWMutex
	context      = make(map[*http.Request]map[string]string)
	bify         = regexp.MustCompile("^(https?://)(.*)$")
	debify       = regexp.MustCompile("^(https?://)(?:(?:birk|wayf)\\.wayf.dk/(?:birk|krib)\\.php/)(.+)$")
	stdtiming    = gosaml.IdAndTiming{time.Now(), 4 * time.Minute, 4 * time.Hour, "", ""}
	postform     = template.Must(template.New("post").Parse(postformtemplate))
	basic2oid    = map[string]string{
		"aRecord":                   "urn:oid:0.9.2342.19200300.100.1.26",
		"aliasedEntryName":          "urn:oid:2.5.4.1",
		"aliasedObjectName":         "urn:oid:2.5.4.1",
		"associatedDomain":          "urn:oid:0.9.2342.19200300.100.1.37",
		"associatedName":            "urn:oid:0.9.2342.19200300.100.1.38",
		"audio":                     "urn:oid:0.9.2342.19200300.100.1.55",
		"authorityRevocationList":   "urn:oid:2.5.4.38",
		"buildingName":              "urn:oid:0.9.2342.19200300.100.1.48",
		"businessCategory":          "urn:oid:2.5.4.15",
		"c":                         "urn:oid:2.5.4.6",
		"cACertificate":             "urn:oid:2.5.4.37",
		"cNAMERecord":               "urn:oid:0.9.2342.19200300.100.1.31",
		"carLicense":                "urn:oid:2.16.840.1.113730.3.1.1",
		"certificateRevocationList": "urn:oid:2.5.4.39",
		"cn":                   "urn:oid:2.5.4.3",
		"co":                   "urn:oid:0.9.2342.19200300.100.1.43",
		"commonName":           "urn:oid:2.5.4.3",
		"countryName":          "urn:oid:2.5.4.6",
		"crossCertificatePair": "urn:oid:2.5.4.40",
		"dITRedirect":          "urn:oid:0.9.2342.19200300.100.1.54",
		"dSAQuality":           "urn:oid:0.9.2342.19200300.100.1.49",
		"dc":                   "urn:oid:0.9.2342.19200300.100.1.25",
		"deltaRevocationList":          "urn:oid:2.5.4.53",
		"departmentNumber":             "urn:oid:2.16.840.1.113730.3.1.2",
		"description":                  "urn:oid:2.5.4.13",
		"destinationIndicator":         "urn:oid:2.5.4.27",
		"displayName":                  "urn:oid:2.16.840.1.113730.3.1.241",
		"distinguishedName":            "urn:oid:2.5.4.49",
		"dmdName":                      "urn:oid:2.5.4.54",
		"dnQualifier":                  "urn:oid:2.5.4.46",
		"documentAuthor":               "urn:oid:0.9.2342.19200300.100.1.14",
		"documentIdentifier":           "urn:oid:0.9.2342.19200300.100.1.11",
		"documentLocation":             "urn:oid:0.9.2342.19200300.100.1.15",
		"documentPublisher":            "urn:oid:0.9.2342.19200300.100.1.56",
		"documentTitle":                "urn:oid:0.9.2342.19200300.100.1.12",
		"documentVersion":              "urn:oid:0.9.2342.19200300.100.1.13",
		"domainComponent":              "urn:oid:0.9.2342.19200300.100.1.25",
		"drink":                        "urn:oid:0.9.2342.19200300.100.1.5",
		"eduOrgHomePageURI":            "urn:oid:1.3.6.1.4.1.5923.1.2.1.2",
		"eduOrgIdentityAuthNPolicyURI": "urn:oid:1.3.6.1.4.1.5923.1.2.1.3",
		"eduOrgLegalName":              "urn:oid:1.3.6.1.4.1.5923.1.2.1.4",
		"eduOrgSuperiorURI":            "urn:oid:1.3.6.1.4.1.5923.1.2.1.5",
		"eduOrgWhitePagesURI":          "urn:oid:1.3.6.1.4.1.5923.1.2.1.6",
		"eduPersonAffiliation":         "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
		"eduPersonAssurance":           "urn:oid:1.3.6.1.4.1.5923.1.1.1.11",
		"eduPersonEntitlement":         "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
		"eduPersonNickname":            "urn:oid:1.3.6.1.4.1.5923.1.1.1.2",
		"eduPersonOrgDN":               "urn:oid:1.3.6.1.4.1.5923.1.1.1.3",
		"eduPersonOrgUnitDN":           "urn:oid:1.3.6.1.4.1.5923.1.1.1.4",
		"eduPersonPrimaryAffiliation":  "urn:oid:1.3.6.1.4.1.5923.1.1.1.5",
		"eduPersonPrimaryOrgUnitDN":    "urn:oid:1.3.6.1.4.1.5923.1.1.1.8",
		"eduPersonPrincipalName":       "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
		"eduPersonScopedAffiliation":   "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
		"eduPersonTargetedID":          "urn:oid:1.3.6.1.4.1.5923.1.1.1.10",
		"email":                        "urn:oid:1.2.840.113549.1.9.1",
		"emailAddress":                 "urn:oid:1.2.840.113549.1.9.1",
		"employeeNumber":               "urn:oid:2.16.840.1.113730.3.1.3",
		"employeeType":                 "urn:oid:2.16.840.1.113730.3.1.4",
		"enhancedSearchGuide":          "urn:oid:2.5.4.47",
		"facsimileTelephoneNumber":     "urn:oid:2.5.4.23",
		"favouriteDrink":               "urn:oid:0.9.2342.19200300.100.1.5",
		"fax":                          "urn:oid:2.5.4.23",
		"federationFeideSchemaVersion": "urn:oid:1.3.6.1.4.1.2428.90.1.9",
		"friendlyCountryName":          "urn:oid:0.9.2342.19200300.100.1.43",
		"generationQualifier":          "urn:oid:2.5.4.44",
		"givenName":                    "urn:oid:2.5.4.42",
		"gn":                           "urn:oid:2.5.4.42",
		"homePhone":                    "urn:oid:0.9.2342.19200300.100.1.20",
		"homePostalAddress":            "urn:oid:0.9.2342.19200300.100.1.39",
		"homeTelephoneNumber":          "urn:oid:0.9.2342.19200300.100.1.20",
		"host":                         "urn:oid:0.9.2342.19200300.100.1.9",
		"houseIdentifier":              "urn:oid:2.5.4.51",
		"info":                         "urn:oid:0.9.2342.19200300.100.1.4",
		"initials":                     "urn:oid:2.5.4.43",
		"internationaliSDNNumber":      "urn:oid:2.5.4.25",
		"isMemberOf":                   "urn:oid:1.3.6.1.4.1.5923.1.5.1.1",
		"janetMailbox":                 "urn:oid:0.9.2342.19200300.100.1.46",
		"jpegPhoto":                    "urn:oid:0.9.2342.19200300.100.1.60",
		"knowledgeInformation":         "urn:oid:2.5.4.2",
		"l":                             "urn:oid:2.5.4.7",
		"labeledURI":                    "urn:oid:1.3.6.1.4.1.250.1.57",
		"localityName":                  "urn:oid:2.5.4.7",
		"mDRecord":                      "urn:oid:0.9.2342.19200300.100.1.27",
		"mXRecord":                      "urn:oid:0.9.2342.19200300.100.1.28",
		"mail":                          "urn:oid:0.9.2342.19200300.100.1.3",
		"mailPreferenceOption":          "urn:oid:0.9.2342.19200300.100.1.47",
		"manager":                       "urn:oid:0.9.2342.19200300.100.1.10",
		"member":                        "urn:oid:2.5.4.31",
		"mobile":                        "urn:oid:0.9.2342.19200300.100.1.41",
		"mobileTelephoneNumber":         "urn:oid:0.9.2342.19200300.100.1.41",
		"nSRecord":                      "urn:oid:0.9.2342.19200300.100.1.29",
		"name":                          "urn:oid:2.5.4.41",
		"norEduOrgAcronym":              "urn:oid:1.3.6.1.4.1.2428.90.1.6",
		"norEduOrgNIN":                  "urn:oid:1.3.6.1.4.1.2428.90.1.12",
		"norEduOrgSchemaVersion":        "urn:oid:1.3.6.1.4.1.2428.90.1.11",
		"norEduOrgUniqueIdentifier":     "urn:oid:1.3.6.1.4.1.2428.90.1.7",
		"norEduOrgUniqueNumber":         "urn:oid:1.3.6.1.4.1.2428.90.1.1",
		"norEduOrgUnitUniqueIdentifier": "urn:oid:1.3.6.1.4.1.2428.90.1.8",
		"norEduOrgUnitUniqueNumber":     "urn:oid:1.3.6.1.4.1.2428.90.1.2",
		"norEduPersonBirthDate":         "urn:oid:1.3.6.1.4.1.2428.90.1.3",
		"norEduPersonLIN":               "urn:oid:1.3.6.1.4.1.2428.90.1.4",
		"norEduPersonNIN":               "urn:oid:1.3.6.1.4.1.2428.90.1.5",
		"o":                             "urn:oid:2.5.4.10",
		"objectClass":                   "urn:oid:2.5.4.0",
		"organizationName":              "urn:oid:2.5.4.10",
		"organizationalStatus":          "urn:oid:0.9.2342.19200300.100.1.45",
		"organizationalUnitName":        "urn:oid:2.5.4.11",
		"otherMailbox":                  "urn:oid:0.9.2342.19200300.100.1.22",
		"ou":                            "urn:oid:2.5.4.11",
		"owner":                         "urn:oid:2.5.4.32",
		"pager":                         "urn:oid:0.9.2342.19200300.100.1.42",
		"pagerTelephoneNumber":          "urn:oid:0.9.2342.19200300.100.1.42",
		"personalSignature":             "urn:oid:0.9.2342.19200300.100.1.53",
		"personalTitle":                 "urn:oid:0.9.2342.19200300.100.1.40",
		"photo":                         "urn:oid:0.9.2342.19200300.100.1.7",
		"physicalDeliveryOfficeName": "urn:oid:2.5.4.19",
		"pkcs9email":                 "urn:oid:1.2.840.113549.1.9.1",
		"postOfficeBox":              "urn:oid:2.5.4.18",
		"postalAddress":              "urn:oid:2.5.4.16",
		"postalCode":                 "urn:oid:2.5.4.17",
		"preferredDeliveryMethod":    "urn:oid:2.5.4.28",
		"preferredLanguage":          "urn:oid:2.16.840.1.113730.3.1.39",
		"presentationAddress":        "urn:oid:2.5.4.29",
		"protocolInformation":        "urn:oid:2.5.4.48",
		"pseudonym":                  "urn:oid:2.5.4.65",
		"registeredAddress":          "urn:oid:2.5.4.26",
		"rfc822Mailbox":              "urn:oid:0.9.2342.19200300.100.1.3",
		"roleOccupant":               "urn:oid:2.5.4.33",
		"roomNumber":                 "urn:oid:0.9.2342.19200300.100.1.6",
		"sOARecord":                  "urn:oid:0.9.2342.19200300.100.1.30",
		"schacCountryOfCitizenship":  "urn:oid:1.3.6.1.4.1.25178.1.2.5",
		"schacCountryOfResidence":    "urn:oid:1.3.6.1.4.1.25178.1.2.11",
		"schacDateOfBirth":           "urn:oid:1.3.6.1.4.1.25178.1.2.3",
		"schacExpiryDate":            "urn:oid:1.3.6.1.4.1.25178.1.2.17",
		"schacGender":                "urn:oid:1.3.6.1.4.1.25178.1.2.2",
		"schacHomeOrganization":      "urn:oid:1.3.6.1.4.1.25178.1.2.9",
		"schacHomeOrganizationType":  "urn:oid:1.3.6.1.4.1.25178.1.2.10",
		"schacMotherTongue":          "urn:oid:1.3.6.1.4.1.25178.1.2.1",
		"schacPersonalPosition":      "urn:oid:1.3.6.1.4.1.25178.1.2.13",
		"schacPersonalTitle":         "urn:oid:1.3.6.1.4.1.25178.1.2.8",
		"schacPersonalUniqueCode":    "urn:oid:1.3.6.1.4.1.25178.1.2.14",
		"schacPersonalUniqueID":      "urn:oid:1.3.6.1.4.1.25178.1.2.15",
		"schacPlaceOfBirth":          "urn:oid:1.3.6.1.4.1.25178.1.2.4",
		"schacProjectMembership":     "urn:oid:1.3.6.1.4.1.25178.1.2.20",
		"schacProjectSpecificRole":   "urn:oid:1.3.6.1.4.1.25178.1.2.21",
		"schacSn1":                   "urn:oid:1.3.6.1.4.1.25178.1.2.6",
		"schacSn2":                   "urn:oid:1.3.6.1.4.1.25178.1.2.7",
		"schacUserPresenceID":        "urn:oid:1.3.6.1.4.1.25178.1.2.12",
		"schacUserPrivateAttribute":  "urn:oid:1.3.6.1.4.1.25178.1.2.18",
		"schacUserStatus":            "urn:oid:1.3.6.1.4.1.25178.1.2.19",
		"schacYearOfBirth":           "urn:oid:1.3.6.1.4.1.25178.1.0.2.3",
		"searchGuide":                "urn:oid:2.5.4.14",
		"secretary":                  "urn:oid:0.9.2342.19200300.100.1.21",
		"seeAlso":                    "urn:oid:2.5.4.34",
		"serialNumber":               "urn:oid:2.5.4.5",
		"singleLevelQuality":         "urn:oid:0.9.2342.19200300.100.1.50",
		"sisSchoolGrade":             "urn:oid:1.2.752.194.10.2.2",
		"sisLegalGuardianFor":        "urn:oid:1.2.752.194.10.2.1",
		"sn": "urn:oid:2.5.4.4",
		"st": "urn:oid:2.5.4.8",
		"stateOrProvinceName":         "urn:oid:2.5.4.8",
		"street":                      "urn:oid:2.5.4.9",
		"streetAddress":               "urn:oid:2.5.4.9",
		"subtreeMaximumQuality":       "urn:oid:0.9.2342.19200300.100.1.52",
		"subtreeMinimumQuality":       "urn:oid:0.9.2342.19200300.100.1.51",
		"supportedAlgorithms":         "urn:oid:2.5.4.52",
		"supportedApplicationContext": "urn:oid:2.5.4.30",
		"surname":                     "urn:oid:2.5.4.4",
		"telephoneNumber":             "urn:oid:2.5.4.20",
		"teletexTerminalIdentifier":   "urn:oid:2.5.4.22",
		"telexNumber":                 "urn:oid:2.5.4.21",
		"textEncodedORAddress":        "urn:oid:0.9.2342.19200300.100.1.2",
		"title":                       "urn:oid:2.5.4.12",
		"uid":                         "urn:oid:0.9.2342.19200300.100.1.1",
		"uniqueIdentifier":            "urn:oid:0.9.2342.19200300.100.1.44",
		"uniqueMember":                "urn:oid:2.5.4.50",
		"userCertificate":             "urn:oid:2.5.4.36",
		"userClass":                   "urn:oid:0.9.2342.19200300.100.1.8",
		"userPKCS12":                  "urn:oid:2.16.840.1.113730.3.1.216",
		"userPassword":                "urn:oid:2.5.4.35",
		"userSMIMECertificate":        "urn:oid:2.16.840.1.113730.3.1.40",
		"userid":                      "urn:oid:0.9.2342.19200300.100.1.1",
		"x121Address":                 "urn:oid:2.5.4.24",
		"x500UniqueIdentifier":        "urn:oid:2.5.4.45",
	}
)

func main() {
	//	logwriter, e := syslog.New(syslog.LOG_NOTICE, "goeleven")
	//	if e == nil {
	//		log.SetOutput(logwriter)
	//	}

	//http.HandleFunc("/status", statushandler)
	http.Handle(config["HYBRID_PUBLIC_PREFIX"], http.FileServer(http.Dir(config["HYBRID_PUBLIC"])))
	http.Handle(config["HYBRID_SSO_SERVICE"], appHandler(ssoService))
	http.Handle(config["HYBRID_ACS"], appHandler(acsService))
	http.Handle(config["HYBRID_BIRK"], appHandler(birkService))
	http.Handle(config["HYBRID_KRIB"], appHandler(kribService))
	var err error
	log.Println("listening on ", config["HYBRID_INTERFACE"])
	err = http.ListenAndServeTLS(config["HYBRID_INTERFACE"], config["HYBRID_HTTPS_CERT"], config["HYBRID_HTTPS_KEY"], nil)
	if err != nil {
		log.Printf("main(): %s\n", err)
	}
}

func memyselfi(r *http.Request, mdSource string) (md *gosaml.Xp, err error) {
	e := "https://" + r.Host + r.URL.Path
	// fix when hub md can be looked up by location
	//if e == (config["HYBRID_HUB"] + config["HYBRID_SSO_SERVICE"]) {
	//	e = config["HYBRID_HUB"]
	//}
	md, _, err = lMDQ.MDQ(mdSource, e)
	return
}

func receiveRequest(samlrequest, mdSource string) (request, md *gosaml.Xp, err error) {
	//  to-do:
	//      schema is checked, timing is checked, acs is checked
	if samlrequest == "" {
		err = errors.New("No SAMLRequest found")
		return
	}
	req, _ := base64.StdEncoding.DecodeString(samlrequest)
	request = gosaml.NewXp(gosaml.Inflate(req))
	issuer := request.Query1(nil, "/samlp:AuthnRequest/saml:Issuer")
	md, _, err = lMDQ.MDQ(mdSource, issuer)
	return
}

func receiveResponse(r *http.Request, mdSource string) (response, md *gosaml.Xp, err error) {

	samlresponse := r.PostFormValue("SAMLResponse")
	if samlresponse == "" {
		err = errors.New("no SAMLResponse found in form")
		return
	}
	samlresponse2, err := base64.StdEncoding.DecodeString(samlresponse)
	if err != nil {
		return
	}
	// receive response -> schema checked, signing checked, timingchecked
	// -> response, issuer md, self md
	response = gosaml.NewXp(samlresponse2)
	md, _, err = lMDQ.MDQ(mdSource, response.Query1(nil, "/samlp:Response/saml:Issuer"))
	return
}

func normalizeResponse(response *gosaml.Xp) (err error) {
    const (
        basic = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
        uri   = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    )

	attributes := response.Query(nil, `//saml:AttributeStatement/saml:Attribute`)

	for _, attribute := range attributes {
		if attribute.GetAttr("NameFormat") == basic {
		    friendlyName := attribute.GetAttr("Name")
			attribute.SetAttr("NameFormat", uri)
			attribute.SetAttr("Name", basic2oid[friendlyName])
			attribute.SetAttr("FriendlyName", friendlyName)
		}
	}
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
	request, _, err := receiveRequest(r.URL.Query().Get("SAMLRequest"), "HUB_OPS")
	if err != nil {
		return
	}
	md, err := memyselfi(r, "HUB")
	if err != nil {
	    return
	}
	idp := md.Query1(nil, "IDPList/ProviderID")
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
		http.Redirect(w, r, config["HYBRID_DISCOVERY"]+data.Encode(), http.StatusFound)
	} else {
	    var idpmd *gosaml.Xp
		acs := request.Query1(nil, "./@AssertionConsumerServiceURL")
		acsurl := bify.ReplaceAllString(acs, "${1}wayf.wayf.dk/krib.php/$2")
		request.QueryDashP(nil, "./@AssertionConsumerServiceURL", acsurl, nil)
		idpmd, _, err = lMDQ.MDQ("EDUGAIN", idp)
		//idpmd, _, err = lMDQ.MDQ("HYBRID_MDQ_HUB_OPS", idp)
		if err != nil {
            return
		}
		const ssoquery = "./md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location"
		ssoservice := idpmd.Query1(nil, ssoquery)
		if ssoservice == "" {

		}

		request.QueryDashP(nil, "./@Destination", ssoservice, nil)
		u, _ := gosaml.SAMLRequest2Url(request, "", "", "")
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	return
}

func birkService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	_, _, err = receiveRequest(r.URL.Query().Get("SAMLRequest"), "EDUGAIN")
	if err != nil {
		return
	}
	mdbirkidp, err := memyselfi(r, "BIRK")
	cookievalue := r.URL.Query().Get("SAMLRequest")
	http.SetCookie(w, &http.Cookie{Name: "BIRK", Value: cookievalue, Domain: config["HYBRID_DOMAIN"], Path: "/", Secure: true, HttpOnly: true})

	idp := debify.ReplaceAllString(mdbirkidp.Query1(nil, "./@entityID"), "$1$2")
	mdidp, _, err := lMDQ.MDQ("HUB_OPS", idp)
	mdhub, _, err := lMDQ.MDQ("HUB", config["HYBRID_HUB"])

	// use a std request - we take care of NameID etc in acsService below
	request := gosaml.NewAuthnRequest(stdtiming, mdhub, mdidp)
	log.Println("req:", request.Pp())
	// to-do delete the following line when md for the hub is OK
	request.QueryDashP(nil, "./@AssertionConsumerServiceURL", config["HYBRID_HUB"]+config["HYBRID_ACS"], nil)

	u, _ := gosaml.SAMLRequest2Url(request, "", "", "")
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
	// we checked the request when we received in birkService - we can use it without fear
	authnrequest, spmd, _ := receiveRequest(birk.Value, "EDUGAIN")

	http.SetCookie(w, &http.Cookie{Name: "BIRK", Value: "", MaxAge: -1, Domain: config["HYBRID_DOMAIN"], Path: "/", Secure: true, HttpOnly: true})

	response, _, err := receiveResponse(r, "HUB_OPS")
	if err != nil {
		return
	}
    _ = normalizeResponse(response)
	log.Println("acs in", response.Pp())
	birkmd, _, err := lMDQ.MDQ("BIRK", authnrequest.Query1(nil, "@Destination"))
	// respect nameID in req, give persistent id + all computed attributes + nameformat conversion

	newresponse := gosaml.NewResponse(stdtiming, birkmd, spmd, authnrequest, response)
	acs := newresponse.Query1(nil, "@Destination")
	log.Println("acs out", newresponse.Pp())

	data := formdata{Acs: acs, Samlresponse: base64.StdEncoding.EncodeToString([]byte(newresponse.X2s()))}
	postform.Execute(w, data)
	return
}

func kribService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	// check response - signing, timing etc

	response, _, err := receiveResponse(r, "EDUGAIN")
	if err != nil {
		return
	}
	log.Println("krib in", response.Pp())
	destination := debify.ReplaceAllString(response.Query1(nil, "./@Destination"), "$1$2")
	response.QueryDashP(nil, "./@Destination", destination, nil)
	response.QueryDashP(nil, "./saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient", destination, nil)
	issuer := config["HYBRID_HUB"]
	response.QueryDashP(nil, "./saml:Issuer", issuer, nil)
	response.QueryDashP(nil, "./saml:Assertion/saml:Issuer", issuer, nil)
	log.Println("krib out", response.Pp())

	data := formdata{Acs: destination, Samlresponse: base64.StdEncoding.EncodeToString([]byte(response.X2s()))}
	postform.Execute(w, data)
	return
}

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := make(map[string]string)
	contextmutex.Lock()
	context[r] = ctx
	contextmutex.Unlock()
	starttime := time.Now()
	w.Header().Set("content-Security-Policy", "referrer no-referrer;")

	err := fn(w, r)

	status := 200
	if err != nil {
		status = 500
		http.Error(w, err.Error(), status)
	}
	log.Printf("%s %s %s %+v %1.3f %d %s", r.RemoteAddr, r.Method, r.Host, r.URL, time.Since(starttime).Seconds(), status, err)

	contextmutex.Lock()
	delete(context, r)
	contextmutex.Unlock()
}
