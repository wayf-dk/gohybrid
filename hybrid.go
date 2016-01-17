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
		"HYBRID_HTTPS_KEY":     "/home/mz/src/hybrid/key.pem",
		"HYBRID_HTTPS_CERT":    "/home/mz/src/hybrid/cert.pem",
		"HYBRID_PUBLIC":        "/home/mz/src/hybrid/public",
		"HYBRID_PUBLIC_PREFIX": "/DS/",
		"HYBRID_SSO_SERVICE":   "/saml2/idp/SSOService.php",
		"HYBRID_ACS":           "/module.php/saml/sp/saml2-acs.php/wayf.wayf.dk",
		"HYBRID_BIRK":          "/birk.php/",
		"HYBRID_KRIB":          "/krib.php/",
		"HYBRID_MDQ_HUB":       "https://phph.wayf.dk/MDQ/wayf-hub-public",
		"HYBRID_MDQ_HUB_OPS":   "https://phph.wayf.dk/MDQ/HUB-OPS",
		"HYBRID_MDQ_EDUGAIN":   "https://phph.wayf.dk/MDQ/EDUGAIN",
		"HYBRID_MDQ_BIRK":      "https://phph.wayf.dk/MDQ/BIRK-OPS",
	}

	contextmutex sync.RWMutex
	context      = make(map[*http.Request]map[string]string)
	bify         = regexp.MustCompile("^(https?://)(.*)$")
	debify       = regexp.MustCompile("^(https?://)(?:(?:birk|wayf)\\.wayf.dk/(?:birk|krib)\\.php/)(.+)$")
	stdtiming    = gosaml.IdAndTiming{time.Now(), 4 * time.Minute, 4 * time.Hour, "", ""}
	postform     = template.Must(template.New("post").Parse(postformtemplate))
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

func memyselfi(r *http.Request, mdSource string) (md *gosaml.Xp) {
	e := "https://" + r.Host + r.URL.Path
	// fix when hub md can be looked up by location
	if e == (config["HYBRID_HUB"] + config["HYBRID_SSO_SERVICE"]) {
		e = config["HYBRID_HUB"]
	}
	md = gosaml.NewMD(mdSource, e)
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
	md = gosaml.NewMD(mdSource, issuer)
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
	md = gosaml.NewMD(mdSource, response.Query1(nil, "/samlp:Response/saml:Issuer"))
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
	request, _, err := receiveRequest(r.URL.Query().Get("SAMLRequest"), config["HYBRID_MDQ_HUB_OPS"])
	if err != nil {
		return err
	}
	md := memyselfi(r, config["HYBRID_MDQ_HUB"])
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
		acs := request.Query1(nil, "./@AssertionConsumerServiceURL")
		acsurl := bify.ReplaceAllString(acs, "${1}wayf.wayf.dk/krib.php/$2")
		request.QueryDashP(nil, "./@AssertionConsumerServiceURL", acsurl, nil)
		idpmd := gosaml.NewMD(config["HYBRID_MDQ_EDUGAIN"], idp)
		//idpmd := gosaml.NewMD(config["HYBRID_MDQ_HUB_OPS"], idp)
		if idpmd == nil {

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
	_, _, err = receiveRequest(r.URL.Query().Get("SAMLRequest"), config["HYBRID_MDQ_HUB_OPS"])
	if err != nil {
		return
	}
    mdbirkidp := memyselfi(r, config["HYBRID_MDQ_BIRK"])
	cookievalue := r.URL.Query().Get("SAMLRequest")
	http.SetCookie(w, &http.Cookie{Name: "BIRK", Value: cookievalue, Domain: config["HYBRID_DOMAIN"], Path: "/", Secure: true, HttpOnly: true})

	idp := debify.ReplaceAllString(mdbirkidp.Query1(nil, "./@entityID"), "$1$2")
	mdidp := gosaml.NewMD(config["HYBRID_MDQ_HUB_OPS"], idp)
	mdhub := gosaml.NewMD(config["HYBRID_MDQ_HUB"], config["HYBRID_HUB"])

	// use a std request - we take care of NameID etc in acsService below
	request := gosaml.NewAuthnRequest(stdtiming, mdhub, mdidp)
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
	authnrequest, mdbirk, _ := receiveRequest(birk.Value, config["HYBRID_MDQ_HUB_OPS"])

	http.SetCookie(w, &http.Cookie{Name: "BIRK", Value: "", MaxAge: -1, Domain: config["HYBRID_DOMAIN"], Path: "/", Secure: true, HttpOnly: true})

	response, _, err := receiveResponse(r, config["HYBRID_MDQ_HUB_OPS"])
	if err != nil {
	    return
	}

	spmd := gosaml.NewMD(config["HYBRID_MDQ_HUB_OPS"], authnrequest.Query1(nil, "./saml:Issuer"))
	//mdhub := gosaml.NewMD(config["HYBRID_MDQ_HUB"], config["HYBRID_HUB"])
	// respect nameID in req, give persistent id + all computed attributes + nameformat conversion

	newresponse := gosaml.NewResponse(stdtiming, mdbirk, spmd, authnrequest, response)
	acs := newresponse.Query1(nil, "@Destination")
	data := formdata{Acs: acs, Samlresponse: base64.StdEncoding.EncodeToString([]byte(newresponse.X2s()))}
	postform.Execute(w, data)
	return
}

func kribService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	// check response - signing, timing etc

	response, _, err := receiveResponse(r, config["HYBRID_MDQ_HUB_OPS"])
	if err != nil {
	    return
	}
	destination := debify.ReplaceAllString(response.Query1(nil, "./@Destination"), "$1$2")
	response.QueryDashP(nil, "./@Destination", destination, nil)
	response.QueryDashP(nil, "./saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient", destination, nil)
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
