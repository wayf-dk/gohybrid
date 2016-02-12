/* Hybrid implements the WAYF hybrid architecture
   - support for RelayState
   - does not seem to work: incl. Capitalization content-security-policy: referrer no-referrer;
   - redo no-referer - current version does not work !!!
   - MDQ lookup by location also for hub md

*/

package main

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
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
	"strconv"
	"strings"
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

	postformtemplate = `<html>
<body onload="document.forms[0].submit()">
<form action="{{.Acs}}" method="POST">
<input type=hidden value="{{.Samlresponse}}" name=SAMLResponse />
<input type=submit value="Submit" />
</form>
</body>
</html>`

    basic = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
    uri   = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
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
	elementsToSign = []string{"/samlp:Response/saml:Assertion"}

	hub, hub_ops, edugain *lMDQ.MDQ

	wayfrequestedattributes = []byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://wayf.wayf.dk">
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
      <md:RequestedAttribute FriendlyName="schacPersonalUniqueID" Name="urn:oid:1.3.6.1.4.1.25178.1.2.15" />
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
</md:EntityDescriptor>`)

	//    'eduPersonAffiliation_allowedvalues' => array('student', 'faculty', 'staff', 'affiliate', 'alum', 'employee', 'library-walk-in', 'member'),
	//    'eduPersonAffiliation_membervalues'  => array('student', 'faculty', 'staff', 'employee'),
)

func main() {
	//	logwriter, e := syslog.New(syslog.LOG_NOTICE, "goeleven")
	//	if e == nil {
	//		log.SetOutput(logwriter)
	//	}
	var err error
	if hub, err = new(lMDQ.MDQ).Open("/home/mz/hub.mddb"); err != nil {
	    log.Println(err)
	}
	if hub_ops, err = new(lMDQ.MDQ).Open("/home/mz/hub_ops.mddb"); err != nil {
	    log.Println(err)
	}
	if edugain, err = new(lMDQ.MDQ).Open("/home/mz/edugain.mddb"); err != nil {
	    log.Println(err)
	}

	//http.HandleFunc("/status", statushandler)
	http.Handle(config["HYBRID_PUBLIC_PREFIX"], http.FileServer(http.Dir(config["HYBRID_PUBLIC"])))
	http.Handle(config["HYBRID_SSO_SERVICE"], appHandler(ssoService))
	http.Handle(config["HYBRID_ACS"], appHandler(acsService))
	http.Handle(config["HYBRID_BIRK"], appHandler(birkService))
	http.Handle(config["HYBRID_KRIB"], appHandler(kribService))

	log.Println("listening on ", config["HYBRID_INTERFACE"])
	err = http.ListenAndServeTLS(config["HYBRID_INTERFACE"], config["HYBRID_HTTPS_CERT"], config["HYBRID_HTTPS_KEY"], nil)
	if err != nil {
		log.Printf("main(): %s\n", err)
	}
}

func receiveRequest(samlrequest string, mdSource *lMDQ.MDQ) (request, md *gosaml.Xp, err error) {
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

	md, _, err = mdSource.MDQ(request.Query1(nil, "/samlp:AuthnRequest/saml:Issuer"))
	return
}

func receiveResponse(r *http.Request, mdSource *lMDQ.MDQ) (response, md *gosaml.Xp, err error) {
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

	md, _, err = mdSource.MDQ(response.Query1(nil, "/samlp:Response/saml:Issuer"))

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

func ssoService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	// handle non ok urls gracefully
	// var err error
	// check issuer and acs in md
	// receiveRequest -> request, issuer md, receiver md
	//     check for IDPList 1st in md, then in request then in query
	//     sanitize idp from query or request
	request, _, err := receiveRequest(r.URL.Query().Get("SAMLRequest"), hub_ops)
	if err != nil {
		return
	}
	md, _, err := hub.MDQ("https://"+r.Host+r.URL.Path)
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
		idpmd, _, err = hub_ops.MDQ(idp)
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
	_, _, err = receiveRequest(r.URL.Query().Get("SAMLRequest"), edugain)
	if err != nil {
		return
	}
	mdbirkidp, _, err := hub_ops.MDQ("https://"+r.Host+r.URL.Path)
	// Save the request in a cookie for when the response comes back
	cookievalue := r.URL.Query().Get("SAMLRequest")
	http.SetCookie(w, &http.Cookie{Name: "BIRK", Value: cookievalue, Domain: config["HYBRID_DOMAIN"], Path: "/", Secure: true, HttpOnly: true})

	idp := debify.ReplaceAllString(mdbirkidp.Query1(nil, "@entityID"), "$1$2")
	mdidp, _, err := hub_ops.MDQ(idp)
	mdhub, _, err := hub.MDQ(config["HYBRID_HUB"])

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
	authnrequest, spmd, _ := receiveRequest(birk.Value, edugain)

	http.SetCookie(w, &http.Cookie{Name: "BIRK", Value: "", MaxAge: -1, Domain: config["HYBRID_DOMAIN"], Path: "/", Secure: true, HttpOnly: true})

	response, idp_md, err := receiveResponse(r, hub_ops)
	if err != nil {
		return
	}

	hub_md := gosaml.NewXp(wayfrequestedattributes)
    WayfAttributeHandler(idp_md, hub_md, response)

	birkmd, _, err := hub_ops.MDQ(authnrequest.Query1(nil, "@Destination"))
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

	response, _, err := receiveResponse(r, edugain)
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
	mdhub, _, err = hub.MDQ(config["HYBRID_HUB"])
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

func WayfAttributeHandler(md, hub_md, response *gosaml.Xp) {
	sourceAttributes := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement`)[0]
	idp := response.Query1(nil, "/samlp:Response/saml:Issuer")

	attCS := hub_md.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService")[0]

    // First check for mandatory and multiplicity
	requestedAttributes := hub_md.Query(attCS, `md:RequestedAttribute[not(@computed)]`) // [@isRequired='true' or @isRequired='1']`)
	for _, requestedAttribute := range requestedAttributes {
		name := requestedAttribute.GetAttr("Name")
		friendlyName := requestedAttribute.GetAttr("FriendlyName")
		//nameFormat := requestedAttribute.GetAttr("NameFormat")
		mandatory := hub_md.QueryBool(requestedAttribute, "@mandatory")
		//must := hub_md.QueryBool(requestedAttribute, "@must")
		singular := hub_md.QueryBool(requestedAttribute, "@singular")

		attributes := response.Query(sourceAttributes, `saml:Attribute[@Name="`+name+`" or @Name="`+friendlyName+`"]`)
		if len(attributes) == 0 && (mandatory) {
			_ = fmt.Errorf("Mandatory attribute not present: %s", name)
			return
		}
		for _, attribute := range attributes {
			valueNodes := response.Query(attribute, `saml:AttributeValue`)
			if len(valueNodes) > 1 && singular {
				_ = fmt.Errorf("Multiple values for singular attribute: %s", name)
				return
			}
			attribute.SetAttr("Name", name)
			attribute.SetAttr("FriendlyName", friendlyName)
			attribute.SetAttr("NameFormat", uri)
		}
	}

	// check that the security domain of eppn is one of the domains in the shib:scope list
	// we just check that everything after the (leftmost|rightmost) @ is in the scope list and save the value for later
	eppn := response.Query1(sourceAttributes, "./saml:Attribute[@FriendlyName='eduPersonPrincipalName']/saml:AttributeValue")
	eppnregexp := regexp.MustCompile(`\@([a-zA-Z0-9\.-]+)$`)
	matches := eppnregexp.FindStringSubmatch(eppn)
	if matches == nil {
		fmt.Printf("eppn does not seem to be an eppn: %s", eppn)
	}

	securitydomain := matches[1]

	scope := md.Query(nil, "//shibmd:Scope[.='"+securitydomain+"']")
	if len(scope) == 0 {
		fmt.Println("security domain for eppn does not match any scopes")
	}

	val := md.Query1(nil, "./md:Extensions/wayf:wayf/wayf:wayf_schacHomeOrganizationType")
    gosaml.CpAndSet(sourceAttributes, response, hub_md, attCS, "schacHomeOrganizationType", val)

	val = md.Query1(nil, "./md:Extensions/wayf:wayf/wayf:wayf_schacHomeOrganization")
    gosaml.CpAndSet(sourceAttributes, response, hub_md, attCS, "schacHomeOrganization", val)

	if response.Query1(sourceAttributes, `saml:Attribute[@FriendlyName="displayName"]/saml:AttributeValue`) == "" {
		if cn := response.Query1(sourceAttributes, `saml:Attribute[@FriendlyName="cn"]/saml:AttributeValue`); cn != "" {
		    gosaml.CpAndSet(sourceAttributes, response, hub_md, attCS, "displayName", cn)
		}
	}

	salt := "ab"
	sp := "de"
	uidhashbase := "uidhashbase" + salt + strconv.Itoa(len(idp)) + ":" + idp
	uidhashbase += strconv.Itoa(len(sp)) + ":" + sp + strconv.Itoa(len(eppn)) + ":" + eppn + salt
	eptid := "WAYF-DK-" + hex.EncodeToString(gosaml.Hash(crypto.SHA1, uidhashbase))

    gosaml.CpAndSet(sourceAttributes, response, hub_md, attCS, "eduPersonTargetedID", eptid)

	dkcprpreg := regexp.MustCompile(`^urn:mace:terena.org:schac:personalUniqueID:dk:CPR:(\d\d)(\d\d)(\d\d)(\d)\d\d\d$`)
	for _, cprelement := range response.Query(sourceAttributes, `saml:Attribute[@FriendlyName="schacPersonalUniqueID"]`) {
		// schacPersonalUniqueID is multi - use the first DK cpr found
		cpr := strings.TrimSpace(response.NodeGetContent(cprelement))
		if matches := dkcprpreg.FindStringSubmatch(cpr); len(matches) > 0 {
			cpryear, _ := strconv.Atoi(matches[3])
			c7, _ := strconv.Atoi(matches[4])
			year := strconv.Itoa(yearfromyearandcifferseven(cpryear, c7))

		    gosaml.CpAndSet(sourceAttributes, response, hub_md, attCS, "schacDateOfBirth", year+matches[2]+matches[1])
		    gosaml.CpAndSet(sourceAttributes, response, hub_md, attCS, "schacYearOfBirth", year)
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
	d := sourceAttributes.AddChild(hub_md.CopyNode(hub_md.Query(attCS, `md:RequestedAttribute[@FriendlyName="eduPersonAffiliation"]`)[0], 2))
    for i, epa := range epaAdd {
		response.QueryDashP(d, `saml:AttributeValue[`+ strconv.Itoa(i + 1 ) + `]`, epa, nil)
    }

	d = sourceAttributes.AddChild(hub_md.CopyNode(hub_md.Query(attCS, `md:RequestedAttribute[@FriendlyName="eduPersonScopedAffiliation"]`)[0], 2))
	i := 1
    for epa, _ := range epaset {
        if epsas[epa] {
            continue
        }
		response.QueryDashP(d, `saml:AttributeValue[`+ strconv.Itoa(i) + `]`, epa + "@" + securitydomain, nil)
		i += 1

    }
	// legal affiliations 'student', 'faculty', 'staff', 'affiliate', 'alum', 'employee', 'library-walk-in', 'member'
	// affiliations => scopedaffiliations
}

//
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

