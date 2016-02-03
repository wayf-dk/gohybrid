/* Hybrid implements the WAYF hybrid architecture
   - support for RelayState
   - does not seem to work: incl. Capitalization content-security-policy: referrer no-referrer;
   - redo no-referer - current version does not work !!!
   - MDQ lookup by location also for hub md

*/

package main

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/lMDQ"
	"html/template"
	"io/ioutil"
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
	idpCertQuery = `./md:IDPSSODescriptor/md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`
	samlSchema   = "/home/mz/src/github.com/wayf-dk/gosaml/schemas/saml-schema-protocol-2.0.xsd"
	certPath     = "/etc/ssl/wayf/signing/"

	HUB_MD    = "HUB"
	INTRA_FED = "HUB_OPS"
	INTER_FED = "EDUGAIN"

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
	}

	contextmutex sync.RWMutex
	context      = make(map[*http.Request]map[string]string)
	bify         = regexp.MustCompile("^(https?://)(.*)$")
	debify       = regexp.MustCompile("^(https?://)(?:(?:birk|wayf)\\.wayf.dk/(?:birk|krib)\\.php/)(.+)$")
	stdtiming    = gosaml.IdAndTiming{time.Now(), 4 * time.Minute, 4 * time.Hour, "", ""}
	postform     = template.Must(template.New("post").Parse(postformtemplate))
	basic2oid    = map[string]string{
		"sn": "urn:oid:2.5.4.4",
		"gn": "urn:oid:2.5.4.42",
		"cn": "urn:oid:2.5.4.3",
		"eduPersonPrincipalName": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
		"mail": "urn:oid:0.9.2342.19200300.100.1.3",
		"eduPersonPrimaryAffiliation": "urn:oid:1.3.6.1.4.1.5923.1.1.1.5",
		"organizationName":            "urn:oid:2.5.4.10",
		"eduPersonAssurance":          "urn:oid:1.3.6.1.4.1.5923.1.1.1.11",
		"schacPersonalUniqueID":       "urn:oid:1.3.6.1.4.1.25178.1.2.15",
		"schacCountryOfCitizenship":   "urn:oid:1.3.6.1.4.1.25178.1.2.5",
		"eduPersonScopedAffiliation":  "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
		"preferredLanguage":           "urn:oid:2.16.840.1.113730.3.1.39",
		"eduPersonEntitlement":        "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
		"norEduPersonLIN":             "urn:oid:1.3.6.1.4.1.2428.90.1.4",
		//		"schacHomeOrganization":      "urn:oid:1.3.6.1.4.1.25178.1.2.9",
		//		"eduPersonTargetedID":          "urn:oid:1.3.6.1.4.1.5923.1.1.1.10",
		"schacDateOfBirth":          "urn:oid:1.3.6.1.4.1.25178.1.2.3",
		"schacYearOfBirth":          "urn:oid:1.3.6.1.4.1.25178.1.0.2.3",
		"schacHomeOrganizationType": "urn:oid:1.3.6.1.4.1.25178.1.2.10",
		"eduPersonAffiliation":      "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
		"displayName":               "urn:oid:2.16.840.1.113730.3.1.241",
	}

	elementsToSign = []string{"/samlp:Response/saml:Assertion"}

	//    'eduPersonAffiliation_allowedvalues' => array('student', 'faculty', 'staff', 'affiliate', 'alum', 'employee', 'library-walk-in', 'member'),
	//    'eduPersonAffiliation_membervalues'  => array('student', 'faculty', 'staff', 'employee'),

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

func receiveRequest(samlrequest, mdSource string) (request, md *gosaml.Xp, err error) {
	//  to-do:
	//      schema is checked, timing is checked, acs is checked
	if samlrequest == "" {
		err = errors.New("No SAMLRequest found")
		return
	}
	req, _ := base64.StdEncoding.DecodeString(samlrequest)
	request = gosaml.NewXp(gosaml.Inflate(req))
	if _, err = request.SchemaValidate(samlSchema); err != nil {
		return
	}

	md, _, err = lMDQ.MDQ(mdSource, request.Query1(nil, "/samlp:AuthnRequest/saml:Issuer"))
	return
}

func receiveResponse(r *http.Request, mdSource string) (response, md *gosaml.Xp, err error) {
	samlresponse := r.PostFormValue("SAMLResponse")
	if samlresponse == "" {
		err = errors.New("No SAMLResponse found")
		return
	}
	samlresponse2, err := base64.StdEncoding.DecodeString(samlresponse)
	if err != nil {
		return
	}
	// receive response -> schema checked, signing checked, timingchecked
	// -> response, issuer md, self md
	response = gosaml.NewXp(samlresponse2)
	if _, err = response.SchemaValidate(samlSchema); err != nil {
		return
	}

	md, _, err = lMDQ.MDQ(mdSource, response.Query1(nil, "/samlp:Response/saml:Issuer"))

	certificates := md.Query(nil, idpCertQuery)
	if len(certificates) == 0 {
		err = errors.New("no certificates found in metadata")
		return
	}

	signatures := response.Query(nil, "(/samlp:Response[ds:Signature] | /samlp:Response/saml:Assertion[ds:Signature])")
	verified := 0
	for _, certificate := range certificates {
		var key *rsa.PublicKey
		_, key, err = gosaml.PublicKeyInfo(md.NodeGetContent(certificate))

		if err != nil {
			return
		}

		for _, signature := range signatures {
			if response.VerifySignature(signature, key) {
				verified++
			}
		}
	}
	if verified == 0 || verified != len(signatures) {
		err = errors.New("Signature check failed")
		return
	}
	return
}

func signResponse(response *gosaml.Xp, elementQuery string, md *gosaml.Xp) (err error) {
	cert := md.Query1(nil, idpCertQuery) // actual signing key is always first
	var keyname string
	keyname, _, err = gosaml.PublicKeyInfo(cert)
	if err != nil {
		return
	}

	var privatekey []byte
	privatekey, err = ioutil.ReadFile(certPath + keyname + ".key")
	if err != nil {
		return
	}

	element := response.Query(nil, elementQuery)
	if len(element) != 1 {
		err = errors.New("Did not find exactly one element to sign")
		return
	}
	err = response.Sign(element[0], string(privatekey), "-", cert, "sha1")
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
	request, _, err := receiveRequest(r.URL.Query().Get("SAMLRequest"), INTRA_FED)
	if err != nil {
		return
	}
	md, _, err := lMDQ.MDQ(HUB_MD, "https://"+r.Host+r.URL.Path)
	if err != nil {
		return
	}
	idp := md.Query1(nil, "IDPList/ProviderID") // Need to find a place for IDPList
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
		acs := request.Query1(nil, "@AssertionConsumerServiceURL")
		acsurl := bify.ReplaceAllString(acs, "${1}wayf.wayf.dk/krib.php/$2")
		request.QueryDashP(nil, "@AssertionConsumerServiceURL", acsurl, nil)
		idpmd, _, err = lMDQ.MDQ(INTER_FED, idp)
		if err != nil {
			return
		}
		const ssoquery = "./md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location"
		ssoservice := idpmd.Query1(nil, ssoquery)
		if ssoservice == "" {

		}

		request.QueryDashP(nil, "@Destination", ssoservice, nil)
		u, _ := gosaml.SAMLRequest2Url(request, "", "", "")
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	return
}

func birkService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	_, _, err = receiveRequest(r.URL.Query().Get("SAMLRequest"), INTER_FED)
	if err != nil {
		return
	}
	mdbirkidp, _, err := lMDQ.MDQ(INTER_FED, "https://"+r.Host+r.URL.Path)
	// Save the request in a cookie for when the response comes back
	cookievalue := r.URL.Query().Get("SAMLRequest")
	http.SetCookie(w, &http.Cookie{Name: "BIRK", Value: cookievalue, Domain: config["HYBRID_DOMAIN"], Path: "/", Secure: true, HttpOnly: true})

	idp := debify.ReplaceAllString(mdbirkidp.Query1(nil, "@entityID"), "$1$2")
	mdidp, _, err := lMDQ.MDQ(INTRA_FED, idp)
	mdhub, _, err := lMDQ.MDQ(HUB_MD, config["HYBRID_HUB"])

	// use a std request - we take care of NameID etc in acsService below
	request := gosaml.NewAuthnRequest(stdtiming, mdhub, mdidp)
	// to-do delete the following line when md for the hub is OK
	request.QueryDashP(nil, "@AssertionConsumerServiceURL", config["HYBRID_HUB"]+config["HYBRID_ACS"], nil)

	u, _ := gosaml.SAMLRequest2Url(request, "", "", "") // not signed so blank key, pw and algo
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
	authnrequest, spmd, _ := receiveRequest(birk.Value, INTER_FED)

	http.SetCookie(w, &http.Cookie{Name: "BIRK", Value: "", MaxAge: -1, Domain: config["HYBRID_DOMAIN"], Path: "/", Secure: true, HttpOnly: true})

	response, _, err := receiveResponse(r, INTRA_FED)
	if err != nil {
		return
	}
	_ = normalizeResponse(response)
	birkmd, _, err := lMDQ.MDQ(INTER_FED, authnrequest.Query1(nil, "@Destination"))
	// respect nameID in req, give persistent id + all computed attributes + nameformat conversion

	newresponse := gosaml.NewResponse(stdtiming, birkmd, spmd, authnrequest, response)

	for _, q := range elementsToSign {
		err = signResponse(newresponse, q, birkmd)
		if err != nil {
			return
		}
	}

	// when consent as a service is ready - we will post to that
	acs := newresponse.Query1(nil, "@Destination")

	data := formdata{Acs: acs, Samlresponse: base64.StdEncoding.EncodeToString([]byte(newresponse.X2s()))}
	postform.Execute(w, data)
	return
}

func kribService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	// check response - signing, timing etc

	response, _, err := receiveResponse(r, INTER_FED)
	if err != nil {
		return
	}
	destination := debify.ReplaceAllString(response.Query1(nil, "@Destination"), "$1$2")
	response.QueryDashP(nil, "@Destination", destination, nil)
	response.QueryDashP(nil, "./saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient", destination, nil)
	issuer := config["HYBRID_HUB"]
	response.QueryDashP(nil, "./saml:Issuer", issuer, nil)
	response.QueryDashP(nil, "./saml:Assertion/saml:Issuer", issuer, nil)

	var mdhub *gosaml.Xp
	mdhub, _, err = lMDQ.MDQ(HUB_MD, config["HYBRID_HUB"])
	if err != nil {
		return
	}

	for _, q := range elementsToSign {
		err = signResponse(response, q, mdhub)
		if err != nil {
			return
		}
	}

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
