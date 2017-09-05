package main

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/spf13/viper"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/gohybrid"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type (
	appHandler func(http.ResponseWriter, *http.Request) error

	md struct {
		entities map[string]*goxml.Xp
	}
)

var (
	hybrid                                                          map[string]string
	certpath, samlSchema, postformtemplate, hubfrequestedattributes string
	hub, internal, external                                         md
	idp_md, idp_md_birk, sp_md, sp_md_krib, hub_md                  *goxml.Xp
	stdtiming                                                       = gosaml.IdAndTiming{time.Now(), 4 * time.Minute, 4 * time.Hour, "", ""}
	basic2uri                                                       map[string]string
)

func main() {
	viper.SetConfigName("hybrid-config")
	viper.AddConfigPath(".")
	viper.SetConfigType("toml")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
	hybrid = viper.GetStringMapString("hybrid")

	//elementsToSign := []string{"/samlp:Response/saml:Assertion"}
	basic2uri = make(map[string]string)

	hub = md{entities: make(map[string]*goxml.Xp)}
	prepareMetadata(viper.GetString(`metadata.hub`), &hub)

	internal = md{entities: make(map[string]*goxml.Xp)}
	prepareMetadata(viper.GetString(`metadata.internal`), &internal)

	external = md{entities: make(map[string]*goxml.Xp)}
	prepareMetadata(viper.GetString(`metadata.external`), &external)

	attrs := goxml.NewXp(hybrid["hubrequestedattributes"])
	for _, attr := range attrs.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute") {
		friendlyName, _ := attr.(types.Element).GetAttribute("FriendlyName")
		name, _ := attr.(types.Element).GetAttribute("Name")
		basic2uri[friendlyName.NodeValue()] = name.NodeValue()
	}

	config := gohybrid.Conf{
		DiscoveryService:       hybrid["discoveryservice"],
		Domain:                 hybrid["domain"],
		HubEntityID:            hybrid["hubentityid"],
		EptidSalt:              hybrid["eptidsalt"],
		HubRequestedAttributes: attrs,
		Internal:               internal,
		External:               external,
		Hub:                    hub,
		SecureCookieHashKey:    hybrid["securecookiehashkey"],
		PostFormTemplate:       hybrid["postformtemplate"],
		Basic2uri:              basic2uri,
		StdTiming:              stdtiming,
		ElementsToSign:         []string{"/samlp:Response/saml:Assertion"},
		AttributeHandler:       WayfAttributeHandler,
	}

	gohybrid.Config(config)

	//http.HandleFunc("/status", statushandler)
	//http.Handle(config["hybrid_public_prefix"], http.FileServer(http.Dir(config["hybrid_public"])))
	http.Handle(hybrid["sso_service"], appHandler(gohybrid.SsoService))
	http.Handle(hybrid["acs"], appHandler(gohybrid.AcsService))
	http.Handle(hybrid["nemlogin_acs"], appHandler(gohybrid.AcsService))
	http.Handle(hybrid["birk"], appHandler(gohybrid.BirkService))
	http.Handle(hybrid["krib"], appHandler(gohybrid.KribService))
	http.Handle(hybrid["testsp_acs"], appHandler(testSPACService))
	http.Handle(hybrid["testsp"]+"/", appHandler(testSPService)) // need a root "/" for routing
	http.Handle(hybrid["testsp"]+"/favicon.ico", http.NotFoundHandler())

	log.Println("listening on ", hybrid["interface"])
	err = http.ListenAndServeTLS(hybrid["interface"], hybrid["https_cert"], hybrid["https_key"], nil)
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

func (m md) MDQ(key string) (xp *goxml.Xp, err error) {
	xp = m.entities[key]
	if xp == nil {
		err = fmt.Errorf("Not found: " + key)
	}
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

func testSPService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	sp_md, _ := internal.MDQ("https://" + hybrid["testsp"])
	hub_md, _ := hub.MDQ(hybrid["hubentityid"])
	fmt.Println("md:", sp_md, hub_md)
	newrequest := gosaml.NewAuthnRequest(stdtiming.Refresh(), sp_md, hub_md)
	u, _ := gosaml.SAMLRequest2Url(newrequest, "", "", "") // not signed so blank key, pw and algo
	q := u.Query()
	q.Set("idpentityid", "https://birk.wayf.dk/birk.php/wayf.ait.dtu.dk/saml2/idp/metadata.php")
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
	return
}

func testSPACService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	response, _, _, err := gosaml.ReceiveSAMLResponse(r, hub, internal)
	if err != nil {
		log.Println(err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8") // normal header
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response.PP()))
	log.Println(response.Doc.Dump(true))
	return
}

func WayfAttributeHandler(idp_md, hub_md, sp_md, response *goxml.Xp) (err error) {
	idp := response.Query1(nil, "/samlp:Response/saml:Issuer")

	if idp == "https://saml.nemlog-in.dk" {
		nemloginAttributeHandler(response)
	}

	sourceAttributes := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement[1]`)[0]
	destinationAttributes := response.QueryDashP(nil, `/saml:Assertion/saml:AttributeStatement[2]`, "", nil)

	base64encoded := idp_md.Query1(nil, "//wayf:base64attributes") == "1"

	attCS := hub_md.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService")[0]

	// First check for required and multiplicity
	requestedAttributes := hub_md.Query(attCS, `md:RequestedAttribute[not(@computed)]`) // [@isRequired='true' or @isRequired='1']`)
	for _, requestedAttribute := range requestedAttributes {
		node, _ := requestedAttribute.(types.Element).GetAttribute("Name")
		name := node.NodeValue()
		node, _ = requestedAttribute.(types.Element).GetAttribute("FriendlyName")
		friendlyName := node.NodeValue()
		//nameFormat := requestedAttribute.GetAttr("NameFormat")
		isRequired := hub_md.QueryBool(requestedAttribute.(types.Element), "@isRequired")
		//must := hub_md.QueryBool(requestedAttribute, "@must")
		singular := hub_md.QueryBool(requestedAttribute.(types.Element), "@singular")

		// accept attributes in both uri and basic format
		attributesValues := response.Query(sourceAttributes, `saml:Attribute[@Name="`+name+`" or @Name="`+friendlyName+`"]/saml:AttributeValue`)
		if len(attributesValues) == 0 && isRequired {
			err = fmt.Errorf("isRequired: %s", friendlyName)
			return
		}
		if len(attributesValues) > 1 && singular {
			err = fmt.Errorf("multiple values for singular attribute: %s", name)
			return
		}
		if len(attributesValues) == 0 {
			continue
		}
		attr := response.QueryDashP(destinationAttributes, `saml:Attribute[@Name="`+name+`"]`, "", nil)
		attr.(types.Element).SetAttribute("FriendlyName", friendlyName)
		attr.(types.Element).SetAttribute("NameFormat", gosaml.Uri)
		index := 1
		for _, node := range attributesValues {
			value := node.NodeValue()
			if base64encoded {
				v, _ := base64.StdEncoding.DecodeString(value)
				value = string(v)
			}
			response.QueryDashP(attr, "saml:AttributeValue["+strconv.Itoa(index)+"]", value, nil)
			index++
		}
	}

	parent, _ := sourceAttributes.ParentNode()
	parent.RemoveChild(sourceAttributes)

	// check that the security domain of eppn is one of the domains in the shib:scope list
	// we just check that everything after the (leftmost|rightmost) @ is in the scope list and save the value for later
	eppn := response.Query1(destinationAttributes, "saml:Attribute[@Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.6']/saml:AttributeValue")
	eppnregexp := regexp.MustCompile(`^[^\@]+\@([a-zA-Z0-9\.-]+)$`)
	matches := eppnregexp.FindStringSubmatch(eppn)
	fmt.Println("eppn", eppn, matches)
	if len(matches) != 2 {
		err = fmt.Errorf("eppn does not seem to be an eppn: %s", eppn)
		return
	}

	securitydomain := matches[1]

	scope := idp_md.Query(nil, "//shibmd:Scope[.='"+securitydomain+"']")
	if len(scope) == 0 {
		err = fmt.Errorf("security domain '%s' for eppn does not match any scopes", securitydomain)
		return
	}

	val := idp_md.Query1(nil, "./md:Extensions/wayf:wayf/wayf:wayf_schacHomeOrganizationType")
	setAttribute("schacHomeOrganizationType", val, response, destinationAttributes)

	val = idp_md.Query1(nil, "./md:Extensions/wayf:wayf/wayf:wayf_schacHomeOrganization")
	setAttribute("schacHomeOrganization", val, response, destinationAttributes)

	if response.Query1(destinationAttributes, `saml:Attribute[@FriendlyName="displayName"]/saml:AttributeValue`) == "" {
		if cn := response.Query1(destinationAttributes, `saml:Attribute[@FriendlyName="cn"]/saml:AttributeValue`); cn != "" {
			setAttribute("displayName", cn, response, destinationAttributes)
		}
	}

	sp := sp_md.Query1(nil, "@entityID")

	uidhashbase := "uidhashbase" + hybrid["eptidsalt"]
	uidhashbase += strconv.Itoa(len(idp)) + ":" + idp
	uidhashbase += strconv.Itoa(len(sp)) + ":" + sp
	uidhashbase += strconv.Itoa(len(eppn)) + ":" + eppn
	uidhashbase += hybrid["eptidsalt"]
	eptid := "WAYF-DK-" + hex.EncodeToString(goxml.Hash(crypto.SHA1, uidhashbase))

	setAttribute("eduPersonTargetedID", eptid, response, destinationAttributes)

	dkcprpreg := regexp.MustCompile(`^urn:mace:terena.org:schac:personalUniqueID:dk:CPR:(\d\d)(\d\d)(\d\d)(\d)\d\d\d$`)
	for _, cprelement := range response.Query(destinationAttributes, `saml:Attribute[@FriendlyName="schacPersonalUniqueID"]`) {
		// schacPersonalUniqueID is multi - use the first DK cpr found
		cpr := strings.TrimSpace(cprelement.NodeValue())
		if matches := dkcprpreg.FindStringSubmatch(cpr); len(matches) > 0 {
			cpryear, _ := strconv.Atoi(matches[3])
			c7, _ := strconv.Atoi(matches[4])
			year := strconv.Itoa(yearfromyearandcifferseven(cpryear, c7))

			setAttribute("schacDateOfBirth", year+matches[2]+matches[1], response, destinationAttributes)
			setAttribute("schacYearOfBirth", year, response, destinationAttributes)
			break
		}
	}

	subsecuritydomain := "." + securitydomain
	epsas := make(map[string]bool)

	for _, epsa := range response.QueryMulti(destinationAttributes, `saml:Attribute[@FriendlyName="eduPersonScopedAffiliation"]/saml:AttributeValue`) {
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
	eppa := response.Query1(destinationAttributes, `saml:Attribute[@FriendlyName="eduPersonPrimaryAffiliation"]`)
	eppa = strings.TrimSpace(eppa)
	epas := response.QueryMulti(destinationAttributes, `saml:Attribute[@FriendlyName="eduPersonAffiliation"]`)
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
	_ = destinationAttributes.AddChild(newattribute)
	for i, epa := range epaAdd {
		response.QueryDashP(newattribute, `saml:AttributeValue[`+strconv.Itoa(i+1)+`]`, epa, nil)
	}
	newattribute, _ = hub_md.Query(attCS, `md:RequestedAttribute[@FriendlyName="eduPersonScopedAffiliation"]`)[0].Copy()
	_ = destinationAttributes.AddChild(newattribute)
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

func nemloginAttributeHandler(response *goxml.Xp) {
	sourceAttributes := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement`)[0].(types.Element)
	value := response.Query1(sourceAttributes, `./saml:Attribute[@Name="urn:oid:2.5.4.3"]/saml:AttributeValue`)
	names := strings.Split(value, " ")
	l := len(names) - 1
	setAttribute("cn", value, response, sourceAttributes)
	setAttribute("gn", strings.Join(names[0:l], " "), response, sourceAttributes)
	setAttribute("sn", names[l], response, sourceAttributes)
	value = response.Query1(sourceAttributes, `./saml:Attribute[@Name="urn:oid:0.9.2342.19200300.100.1.1"]/saml:AttributeValue`)
	setAttribute("eduPersonPrincipalName", value+"@sikker-adgang.dk", response, sourceAttributes)
	value = response.Query1(sourceAttributes, `./saml:Attribute[@Name="urn:oid:0.9.2342.19200300.100.1.3"]/saml:AttributeValue`)
	setAttribute("mail", value, response, sourceAttributes)
	value = response.Query1(sourceAttributes, `./saml:Attribute[@Name="dk:gov:saml:Attribute:AssuranceLevel"]/saml:AttributeValue`)
	setAttribute("eduPersonAssurance", value, response, sourceAttributes)
	value = response.Query1(sourceAttributes, `./saml:Attribute[@Name="dk:gov:saml:Attribute:CprNumberIdentifier"]/saml:AttributeValue`)
	setAttribute("schacPersonalUniqueID", "urn:mace:terena.org:schac:personalUniqueID:dk:CPR:"+value, response, sourceAttributes)
	setAttribute("eduPersonPrimaryAffiliation", "member", response, sourceAttributes)
	setAttribute("schacHomeOrganization", "http://sikker-adgang.dk", response, sourceAttributes)
	setAttribute("organizationName", "NemLogin", response, sourceAttributes)
}

func setAttribute(name, value string, response *goxml.Xp, element types.Node) {
	attr := response.QueryDashP(element.(types.Element), `/saml:Attribute[@Name="`+basic2uri[name]+`"]`, "", nil)
	response.QueryDashP(attr, `./@NameFormat`, gosaml.Uri, nil)
	response.QueryDashP(attr, `./@FriendlyName`, name, nil)
	values := len(response.Query(attr, `./saml:AttributeValue`)) + 1
	response.QueryDashP(attr, `./saml:AttributeValue[`+strconv.Itoa(values)+`]`, value, nil)
}

func b64ToString(enc string) string {
	dec, _ := base64.StdEncoding.DecodeString(enc)
	return string(dec)
}
