/*
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

package gohybrid

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/securecookie"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sync"
)

type (
	formdata struct {
		Acs          string
		Samlresponse string
		RelayState   string
		Ard          template.JS
	}

	AttributeReleaseData struct {
		Values         map[string][]string
		IdPDisplayName map[string]string
		IdPLogo        string
		SPDisplayName  map[string]string
		SPDescription  map[string]string
		SPLogo         string
		SPEntityID     string
		Key            string
		Hash           string
	}

	Conf struct {
		DiscoveryService         string
		Domain                   string
		HubEntityID              string
		EptidSalt                string
		HubRequestedAttributes   *goxml.Xp
		Internal, External, Hub  gosaml.Md
		SecureCookieHashKey      string
		PostFormTemplate         string
		AttributeReleaseTemplate string
		Basic2uri                map[string]string
		StdTiming                gosaml.IdAndTiming
		ElementsToSign           []string
		Certpath                 string
		SSOServiceHandler        func(*goxml.Xp, *goxml.Xp, *goxml.Xp, *goxml.Xp) (string, string, error)
		BirkHandler              func(*goxml.Xp, *goxml.Xp, *goxml.Xp) (*goxml.Xp, *goxml.Xp, error)
		AttributeHandler         func(*goxml.Xp, *goxml.Xp, *goxml.Xp, *goxml.Xp) (AttributeReleaseData, error)
	}
)

const (
	idpCertQuery = `./md:IDPSSODescriptor/md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`
	spCertQuery  = `./md:SPSSODescriptor/md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`
)

var (
	_ = log.Printf // For debugging; delete when done.
	_ = fmt.Printf

	contextmutex sync.RWMutex
	context      = make(map[*http.Request]map[string]string)
	debify       = regexp.MustCompile("^(https?://)(?:(?:birk|krib)\\.wayf.dk/(?:birk|krib)\\.php/)(.+)$")

	postForm, attributeReleaseForm *template.Template
	hashKey                        []byte
	seccookie                      *securecookie.SecureCookie
	config                         = Conf{}
)

func Config(configuration Conf) {
	config = configuration
	hashKey, _ := hex.DecodeString(config.SecureCookieHashKey)
	seccookie = securecookie.New(hashKey, nil)
	postForm = template.Must(template.New("post").Parse(config.PostFormTemplate))
	attributeReleaseForm = template.Must(template.New("post").Parse(config.AttributeReleaseTemplate))
}

func SsoService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	request, spmd, hubmd, relayState, err := gosaml.ReceiveSAMLRequest(r, config.Internal, config.Hub)
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
		http.Redirect(w, r, config.DiscoveryService+data.Encode(), http.StatusFound)
	} else {
		idpmd, err := config.External.MDQ(idp)
		if err != nil {
			return err
		}

		kribID, acsurl, err := config.SSOServiceHandler(request, spmd, hubmd, idpmd)
		if err != nil {
			return err
		}

		request.QueryDashP(nil, "/saml:Issuer", kribID, nil)
		request.QueryDashP(nil, "@AssertionConsumerServiceURL", acsurl, nil)

		const ssoquery = "./md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location"
		ssoservice := idpmd.Query1(nil, ssoquery)
		if ssoservice == "" {

		}
		request.QueryDashP(nil, "@Destination", ssoservice, nil)
		u, _ := gosaml.SAMLRequest2Url(request, relayState, "", "", "")
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	return
}

func BirkService(w http.ResponseWriter, r *http.Request) (err error) {
	// use incoming request for crafting the new one
	// remember to add the Scoping element to inform the IdP of requesterID - if stated in metadata for the IdP
	// check ad-hoc feds overlab
	defer r.Body.Close()
	// get the sp as well to check for allowed acs
	request, mdsp, mdbirkidp, relayState, err := gosaml.ReceiveSAMLRequest(r, config.External, config.External)
	if err != nil {
		return
	}
	// Save the issuer and destination in a cookie for when the response comes back

	cookievalue, err := seccookie.Encode("BIRK", gosaml.Deflate(request.Doc.Dump(true)))
	http.SetCookie(w, &http.Cookie{Name: "BIRK", Value: cookievalue, Domain: config.Domain, Path: "/", Secure: true, HttpOnly: true})

	mdhub, mdidp, err := config.BirkHandler(request, mdsp, mdbirkidp)
	if err != nil {
		return
	}

	newrequest := gosaml.NewAuthnRequest(config.StdTiming.Refresh(), mdhub, mdidp)

	var privatekey []byte
	passwd := "-"
	wars := mdidp.Query1(nil, `./md:IDPSSODescriptor/@WantAuthnRequestsSigned`)
	switch wars {
	case "true", "1":
		cert := mdhub.Query1(nil, spCertQuery) // actual signing key is always first
		var keyname string
		keyname, _, err = gosaml.PublicKeyInfo(cert)
		if err != nil {
			return err
		}

		privatekey, err = ioutil.ReadFile(config.Certpath + keyname + ".key")
		if err != nil {
			return
		}
	}

	u, _ := gosaml.SAMLRequest2Url(newrequest, relayState, string(privatekey), passwd, "sha256")
	http.Redirect(w, r, u.String(), http.StatusFound)
	return
}

func AcsService(w http.ResponseWriter, r *http.Request) (err error) {
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
	request := goxml.NewXp(string(gosaml.Inflate(value)))

	http.SetCookie(w, &http.Cookie{Name: "BIRK", Value: "", Domain: config.Domain, Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
	sp_md, err := config.External.MDQ(request.Query1(nil, "/samlp:AuthnRequest/saml:Issuer"))
	if err != nil {
		return
	}

	response, idp_md, _, relayState, err := gosaml.ReceiveSAMLResponse(r, config.Internal, config.Hub)
	if err != nil {
		return
	}

	ard, err := config.AttributeHandler(idp_md, config.HubRequestedAttributes, sp_md, response)
	if err != nil {
		return
	}

	birkmd, err := config.External.MDQ(request.Query1(nil, "/samlp:AuthnRequest/@Destination"))
	if err != nil {
		return
	}
	nameid := response.Query(nil, "./saml:Assertion/saml:Subject/saml:NameID")[0]
	// respect nameID in req, give persistent id + all computed attributes + nameformat conversion
	nameidformat := sp_md.Query1(nil, "./md:SPSSODescriptor/md:NameIDFormat")
	if nameidformat == gosaml.Persistent {
		response.QueryDashP(nameid, "@Format", gosaml.Persistent, nil)
		eptid := response.Query1(nil, `./saml:Assertion/saml:AttributeStatement/saml:Attribute[@FriendlyName="eduPersonTargetedID"]/saml:AttributeValue`)
		response.QueryDashP(nameid, ".", eptid, nil)
	} else if nameidformat == gosaml.Transient {
		response.QueryDashP(nameid, ".", gosaml.Id(), nil)
	}

	newresponse := gosaml.NewResponse(config.StdTiming.Refresh(), birkmd, sp_md, request, response)

	for _, q := range config.ElementsToSign {
		err = gosaml.SignResponse(newresponse, q, birkmd)
		if err != nil {
			return
		}
	}

	// when consent as a service is ready - we will post to that
	acs := newresponse.Query1(nil, "@Destination")

	ardjson, err := json.Marshal(ard)
	data := formdata{Acs: acs, Samlresponse: base64.StdEncoding.EncodeToString([]byte(newresponse.Doc.Dump(false))), RelayState: relayState, Ard: template.JS(ardjson)}
	attributeReleaseForm.Execute(w, data)
	return
}

func KribService(w http.ResponseWriter, r *http.Request) (err error) {
	// check ad-hoc feds overlap
	defer r.Body.Close()

	response, _, _, relayState, err := gosaml.ReceiveSAMLResponse(r, config.External, config.External)
	if err != nil {
		return
	}

	destination := debify.ReplaceAllString(response.Query1(nil, "@Destination"), "$1$2")
	response.QueryDashP(nil, "@Destination", destination, nil)
	response.QueryDashP(nil, "./saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient", destination, nil)
	issuer := config.HubEntityID
	response.QueryDashP(nil, "./saml:Issuer", issuer, nil)
	response.QueryDashP(nil, "./saml:Assertion/saml:Issuer", issuer, nil)
	// Krib always receives attributes with nameformat=urn. Before sending to the real SP we need to look into
	// the metadata for SP to determine the actual nameformat - as WAYF supports both for internal SPs.
	mdsp, err := config.Internal.MDQ(destination)
	if err != nil {
		return
	}
	requestedattributes := mdsp.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute")
	attributestatement := response.Query(nil, "./saml:Assertion/saml:AttributeStatement")[0]
	for _, attr := range requestedattributes {
		nameFormat, _ := attr.(types.Element).GetAttribute("NameFormat")
		if nameFormat.NodeValue() == gosaml.Basic {
			basicname, _ := attr.(types.Element).GetAttribute("Name")
			uriname := config.Basic2uri[basicname.NodeValue()]
			responseattribute := response.Query(attributestatement, "saml:Attribute[@Name='"+uriname+"']")
			if len(responseattribute) > 0 {
				responseattribute[0].(types.Element).SetAttribute("Name", basicname.NodeValue())
				responseattribute[0].(types.Element).SetAttribute("NameFormat", gosaml.Basic)
			}
		}
	}

	mdhub, err := config.Hub.MDQ(config.HubEntityID)
	if err != nil {
		return
	}

	for _, q := range config.ElementsToSign {
		err = gosaml.SignResponse(response, q, mdhub)
		if err != nil {
			return
		}
	}

	data := formdata{Acs: destination, Samlresponse: base64.StdEncoding.EncodeToString([]byte(response.Doc.Dump(false))), RelayState: relayState}
	postForm.Execute(w, data)
	return
}
