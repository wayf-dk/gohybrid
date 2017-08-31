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
	"encoding/xml"
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
	"time"
	//"github.com/gobuffalo/packr"
	"github.com/gorilla/securecookie"
	"github.com/spf13/viper"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
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
	basic        = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	uri          = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	transient    = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	persistent   = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

var (
	_                                                               = log.Printf // For debugging; delete when done.
	_                                                               = fmt.Printf
	config                                                          map[string]string
	certpath, samlSchema, postformtemplate, wayfrequestedattributes string

	remap = map[string]idpsppair{
		"https://nemlogin.wayf.dk": idpsppair{"https://saml.nemlog-in.dk", "https://nemlogin.wayf.dk"},
	}

	contextmutex   sync.RWMutex
	context        = make(map[*http.Request]map[string]string)
	bify           = regexp.MustCompile("^(https?://)(.*)$")
	debify         = regexp.MustCompile("^(https?://)(?:(?:birk|krib)\\.wayf.dk/(?:birk|krib)\\.php/)(.+)$")
	stdtiming      = gosaml.IdAndTiming{time.Now(), 4 * time.Minute, 4 * time.Hour, "", ""}
	elementsToSign = []string{"/samlp:Response/saml:Assertion"}

	postform              *template.Template
	hub, hub_ops, edugain md

	basic2uri                                      = map[string]string{}
	idp_md, idp_md_birk, sp_md, sp_md_krib, hub_md *goxml.Xp

	hashKey   []byte
	seccookie *securecookie.SecureCookie
)

func (m md) MDQ(key string) (xp *goxml.Xp, err error) {
	xp = m.entities[key]
	if xp == nil {
		err = fmt.Errorf("Not found: " + key)
	}
	return
}

func main() {
	viper.SetConfigName("hybrid-config")
	viper.AddConfigPath(".")
	viper.SetConfigType("toml")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
	config = viper.GetStringMapString("config")

	hashKey, err := hex.DecodeString(config["securecookiehashkey"])
	seccookie = securecookie.New(hashKey, nil)

	postform = template.Must(template.New("post").Parse(config["postformtemplate"]))

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

	hub = md{entities: make(map[string]*goxml.Xp)}
	prepareMetadata(viper.GetString(`metadata.hub`), &hub)

	hub_ops = md{entities: make(map[string]*goxml.Xp)}
	prepareMetadata(viper.GetString(`metadata.internal`), &hub_ops)

	edugain = md{entities: make(map[string]*goxml.Xp)}
	prepareMetadata(viper.GetString(`metadata.external`), &edugain)

	attrs := goxml.NewXp(config["wayfrequestedattributes"])
	for _, attr := range attrs.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute") {
		friendlyName, _ := attr.(types.Element).GetAttribute("FriendlyName")
		name, _ := attr.(types.Element).GetAttribute("Name")
		basic2uri[friendlyName.NodeValue()] = name.NodeValue()
	}

	//http.HandleFunc("/status", statushandler)
	//http.Handle(config["hybrid_public_prefix"], http.FileServer(http.Dir(config["hybrid_public"])))
	http.Handle(config["hybrid_sso_service"], appHandler(ssoService))
	http.Handle(config["hybrid_acs"], appHandler(acsService))
	http.Handle(config["nemlogin_acs"], appHandler(acsService))
	http.Handle(config["hybrid_birk"], appHandler(birkService))
	http.Handle(config["hybrid_krib"], appHandler(kribService))
	http.Handle(config["testsp"]+"/", appHandler(testSPService)) // need a root "/" for routing
	http.Handle(config["testsp_acs"], appHandler(testSPACService))

	log.Println("listening on ", config["hybrid_interface"])
	err = http.ListenAndServeTLS(config["hybrid_interface"], config["hybrid_https_cert"], config["hybrid_https_key"], nil)
	if err != nil {
		log.Printf("main(): %s\n", err)
	}
}

func prepareMetadata(metadata string, index *md) {
	indextargets := []string{
		"./md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location",
		"./md:SPSSODescriptor/md:AssertionConsumerService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location",
	}

	x := goxml.NewXp(metadata)
	entities := x.Query(nil, "md:EntityDescriptor")

	for _, entity := range entities {
		newentity := goxml.NewXpFromNode(entity)
		entityID, _ := entity.(types.Element).GetAttribute("entityID")
		index.entities[entityID.Value()] = newentity
		for _, target := range indextargets {
			locations := newentity.Query(nil, target)
			for _, location := range locations {
				index.entities[location.NodeValue()] = newentity
			}
		}
	}
}

func testSPService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	sp_md, _ := hub_ops.MDQ("https://" + config["testsp"])
	hub_md, _ := hub.MDQ(config["hybrid_hub"])
	newrequest := gosaml.NewAuthnRequest(stdtiming.Refresh(), sp_md, hub_md)
	u, _ := gosaml.SAMLRequest2Url(newrequest, "", "", "") // not signed so blank key, pw and algo
	http.Redirect(w, r, u.String(), http.StatusFound)
	return
}

func testSPACService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	response, _, _, err := gosaml.ReceiveSAMLResponse(r, hub, hub_ops)
	if err != nil {
		log.Println(err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8") // normal header
	w.WriteHeader(http.StatusOK)
	w.Write(ppxml(response))
	log.Println(response.Doc.Dump(true))
	return
}

func ppxml(xp *goxml.Xp) (buf []byte) {
	txt := xp.Doc.Dump(true)

	type node struct {
		Attr     []xml.Attr
		XMLName  xml.Name
		Children []node `xml:",any"`
		Text     string `xml:",chardata"`
	}
	x := node{}
	_ = xml.Unmarshal([]byte(txt), &x)
	buf, _ = xml.MarshalIndent(x, "", "\t")
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
		http.Redirect(w, r, config["hybrid_discovery"]+data.Encode(), http.StatusFound)
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

	cookievalue, err := seccookie.Encode("BIRK", gosaml.Deflate(request.Doc.Dump(true)))
	http.SetCookie(w, &http.Cookie{Name: "BIRK", Value: cookievalue, Domain: config["hybrid_domain"], Path: "/", Secure: true, HttpOnly: true})

	idp := debify.ReplaceAllString(mdbirkidp.Query1(nil, "@entityID"), "$1$2")

	var mdhub, mdidp *goxml.Xp
	// are we remapping - for now only use case is https://nemlogin.wayf.dk -> https://saml.nemlog-in.dk
	if rm, ok := remap[idp]; ok {
		mdidp, err = hub_ops.MDQ(rm.idp)
		mdhub, err = hub_ops.MDQ(rm.sp)
	} else {
		mdidp, err = hub_ops.MDQ(idp)
		mdhub, err = hub.MDQ(config["hybrid_hub"])
	}
	// use a std request - we take care of NameID etc in acsService below
	newrequest := gosaml.NewAuthnRequest(stdtiming.Refresh(), mdhub, mdidp)
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

	value := []byte{}
	if err = seccookie.Decode("BIRK", birk.Value, &value); err != nil {
		return
	}

	// we checked the request when we received in birkService - we can use it without fear ie. we just parse it
	log.Println("cookie", string(gosaml.Inflate(value)))
	request := goxml.NewXp(string(gosaml.Inflate(value)))

	http.SetCookie(w, &http.Cookie{Name: "BIRK", Value: "", Domain: config["hybrid_domain"], Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
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

	hub_md := goxml.NewXp(config["wayfrequestedattributes"])
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
	issuer := config["hybrid_hub"]
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

	mdhub, err := hub.MDQ(config["hybrid_hub"])
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
		isRequired := hub_md.QueryBool(requestedAttribute.(types.Element), "@isRequired")
		//must := hub_md.QueryBool(requestedAttribute, "@must")
		singular := hub_md.QueryBool(requestedAttribute.(types.Element), "@singular")

		// accept attributes in both uri and basic format
		attributes := response.Query(sourceAttributes, `saml:Attribute[@Name="`+name.NodeValue()+`" or @Name="`+friendlyName.NodeValue()+`"]`)
		if len(attributes) == 0 && isRequired {
			err = fmt.Errorf("isRequired: %s", friendlyName.NodeValue())
			return
		}
		for _, attribute := range attributes {
			valueNodes := response.Query(attribute, `saml:AttributeValue`)
			if len(valueNodes) > 1 && singular {
				err = fmt.Errorf("multiple values for singular attribute: %s", name.NodeValue())
				return
			}
			if len(valueNodes) != 1 && isRequired {
				err = fmt.Errorf("isRequired: %s", friendlyName.NodeValue())
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
