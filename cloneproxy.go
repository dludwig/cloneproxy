/*
ReverseCloneProxy
- A reverse proxy with a forking of traffic to a clone

You can proxy traffic to production & staging simultaneously.
This can be used for development/testing/benchmarking, it can
also be used to replicate traffic while moving across clouds.

TODO:
-[Done] Create cli with simple reverse proxy (no clone)
-[Done] <<Testing/Checkpoint>>
-[Done] Add struct/interface model for ReverseCloneProxy
-[Done] Should use ServeHTTP which copies the req and calls ServeTargetHTTP
-[Done] <<Testing/Checkpoint>>
-[Done] Add sequential calling of ServeCloneHTTP
-[Done] <<Testing/Checkpoint>>
-[Done] Add support for timeouts on a & b side
-[Done] Sync calling of ServeTargetHTTP & only on success call ServeCloneHTTP
-[Done] <<Testing/Checkpoint>>
-[Done] Cleanup loglevelging & Add logging similar to what was done for our custom teeproxy
-[Done] <<Testing/Checkpoint>>
-[Done] Add in support for percentage of traffic to clone
-[Done] <<Testing/Checkpoint>>
-[Done] Add separate context for clone to prevent context cancel exits.
-[Done-0328] Cleanup context logging & logging in general
-[Done-0328] Add support for Proxy so I can test this thing from my cube
-[Done-0328] Add support for detecting mismatch in target/clone and generate warning
-[Done-0328] Fixed a bug with XFF handling on B side
-[Done-0328] Add very basic timing information for each side & total
-[Done-0331] Add support for debug/service endpoint on /debug/vars
-[Done-0331] Add support regular status log messages (every 15min)
-[Done-0331] Add tracking for matches/mismatches/unfulfilled/skipped
-[Done-0403] Add tracking of duration for all cases
-[Done-0403] Triple check close handling for requests
-[Done-0403] Adjust default params for Transport
-[Done-0403] Add support for increasing socket limits
-[Done-0404] Set client readtimeout & writetimeout
- (Defer to 2.0) Add support for retry on BadGateway on clone (Wait for go 1.9)
- (Defer to 2.0) Add support for detailed performance metrics on target/clone responses (see davecheney/httpstat)
-[Done-0418] Regular status messages as part of default level 1 (Warn) setting
*/

package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"expvar"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/mitchellh/go-homedir"
	"github.com/robfig/cron"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"github.com/urfave/cli"

	// profiling server
	_ "net/http/pprof"
)

var tlsConfig *tls.Config
var tlsConn *tls.Conn

const exclusionFlag = "!"

var (
	// VERSION is the current version of cloneproxy.
	VERSION string
	// formatted datetime during build.
	minversion string
	// the commit this binary was built from.
	build string
	// the go version running this binary.
	goVersion = runtime.Version()

	cloneproxyHeader = "X-Cloneproxy-Request"
	sideServedheader = "X-Cloneproxy-Served"
	cloneproxyXFF    = "X-Cloneproxy-XFF"

	totalMatches     = expvar.NewInt("totalMatches")
	totalMismatches  = expvar.NewInt("totalMismatches")
	totalUnfulfilled = expvar.NewInt("totalUnfulfilled")
	totalSkipped     = expvar.NewInt("totalSkipped")
	timeOrigin       = time.Now()
)

func pathToConfig() string {
	home, err := homedir.Dir()
	if err != nil {
		log.Fatal(err)
	}

	return fmt.Sprintf("%s/.cloneproxy/config.json", home)
}

func configuration(configFile string) {
	viper.SetConfigType("json")
	viper.SetConfigFile(configFile)

	config, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Error, missing %s file", configFile)
	}

	if err = viper.ReadConfig(bytes.NewBuffer(config)); err != nil {
		log.Fatal(err)
	}
}

// **********************************************************************************
// Begin:  Package components  (TODO: Should probably packagize this...)
// **********************************************************************************

// Heavily derived from
// HTTP reverse proxy handler

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// onExitFlushLoop is a callback set by tests to detect the state of the
// flushLoop() goroutine.
var onExitFlushLoop func()

type baseHandle struct{}

// ReverseClonedProxy is an HTTP Handler that takes an incoming request and
// sends it to another server, proxying the response back to the
// client.
type ReverseClonedProxy struct {
	// Director must be a function which modifies
	// the request into a new request to be sent
	// using Transport. Its response is then copied
	// back to the original client unmodified.
	// Director must not access the provided Request
	// after returning.
	Director      func(*http.Request)
	DirectorClone func(*http.Request)

	// The transport used to perform proxy requests.
	// If nil, http.DefaultTransport is used.
	Transport      http.RoundTripper
	TransportClone http.RoundTripper

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	FlushInterval time.Duration

	// ErrorLog specifies an optional logger for errors
	// that occur when attempting to proxy the request.
	// If nil, logging goes to os.Stderr via the log package's
	// standard logger.

	ErrorLog *log.Logger

	// BufferPool optionally specifies a buffer pool to
	// get byte slices for use by io.CopyBuffer when
	// copying HTTP response bodies.
	BufferPool BufferPool

	// ModifyResponse is an optional function that
	// modifies the Response from the backend.
	// If it returns an error, the proxy returns a StatusBadGateway error.
	ModifyResponse func(*http.Response) error
	//ModifyResponseClone func(*http.Response) error
}

// A BufferPool is an interface for getting and returning temporary
// byte slices for use by io.CopyBuffer.
type BufferPool interface {
	Get() []byte
	Put([]byte)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; http://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

func removeHeaders(body string, headers []string) string {
	bodyString := body
	for _, header := range headers {
		bodyString = strings.Replace(bodyString, header, "", -1)
	}
	return bodyString
}

func sha1Body(body []byte, headers []string) string {
	stringBody := string(body)
	hasher := sha1.New()
	hasher.Write([]byte(stringBody))
	return hex.EncodeToString(hasher.Sum(nil))
}

func getConfigPaths(route string) (map[string]interface{}, map[string]interface{}) {
	configPaths := viper.Get("Paths").(map[string]interface{})
	route = strings.ToLower(route)
	if configPaths[route] == nil {
		log.Fatalf("%v not in config", route)
	}
	return configPaths, configPaths[route].(map[string]interface{})
}

func getPathFromConfig(requestURI string) (string, error) {
	requestURI = strings.ToLower(requestURI)
	allPathsMatch := false
	var pathKey string

	for path := range viper.Get("Paths").(map[string]interface{}) {
		if requestURI == path {
			pathKey = path
			return pathKey, nil
		}
		if path == "/" {
			allPathsMatch = true
		}
	}

	if allPathsMatch {
		return "/", nil
	}
	return "", fmt.Errorf("no path contains '%s' in the config file", requestURI)
}

func setCloneproxyHeader(reqHeader http.Header, outreq *http.Request) {
	targetServed := reqHeader.Get(cloneproxyHeader)
	if targetServed != "" {
		count, err := strconv.Atoi(targetServed)
		if err == nil {
			count++
			outreq.Header.Set(cloneproxyHeader, strconv.Itoa(count))
		}
	} else {
		outreq.Header.Set(cloneproxyHeader, "1")
	}
}

func setCloneproxyXFFHeader(outreq *http.Request) string {
	xffHeader := getIP()
	xff := outreq.Header.Get(cloneproxyXFF)
	if xff != "" {
		xffHeader = xff + "," + xffHeader
		outreq.Header.Set(cloneproxyXFF, xffHeader)
	} else {
		outreq.Header.Set(cloneproxyXFF, xffHeader)
	}

	return xffHeader
}

func getIP() string {
	// UDP doesn't have handshake or connection -- therefore, a connection is never established
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.String()
}

// Routes requests to appropriate ReverseCloneProxy handler
func (h *baseHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestURI := r.RequestURI

	if viper.GetBool("EnableRequestProfiling") {
		start := time.Now().UTC().UnixNano()
		defer func() {
			respTime := (time.Now().UTC().UnixNano() - start) / int64(time.Millisecond)
			log.Printf("request for '%v' took %v ms", requestURI, respTime)
		}()
	}

	if r.URL.Path == "/service/ping" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(map[string]string{"msg": "imok"})
		return
	}

	path, err := getPathFromConfig(requestURI)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusNotFound)
		errorMsg := fmt.Sprintf("unable to process request: %v", err)
		json.NewEncoder(w).Encode(map[string]string{"error": errorMsg})
		return
	}

	_, targetClone := getConfigPaths(path)
	configTargetURL := targetClone["target"].(string)
	configCloneURL := targetClone["clone"].(string)
	targetInsecure := targetClone["targetinsecure"].(bool)
	cloneInsecure := targetClone["cloneinsecure"].(bool)

	targetURL := parseURLWithDefaults(configTargetURL)
	cloneURL := parseURLWithDefaults(configCloneURL)

	if !strings.HasPrefix(configTargetURL, "http") && !strings.HasPrefix(configTargetURL, "https") {
		fmt.Printf("Error: target url %s is invalid\n   URL's must have a scheme defined, either http or https\n\n", configTargetURL)
		flag.Usage()
		os.Exit(1)
	}
	if configCloneURL != "" && !strings.HasPrefix(configCloneURL, "http") && !strings.HasPrefix(configCloneURL, "https") {
		fmt.Printf("Error: clone url %s is invalid\n   URL's must have a scheme defined, either http or https\n\n", configCloneURL)
		flag.Usage()
		os.Exit(1)
	}

	proxy := NewCloneProxy(
		targetURL,
		viper.GetInt("TargetTimeout"),
		viper.GetBool("TargetRewrite"),
		targetInsecure,
		cloneURL,
		viper.GetInt("CloneTimeout"),
		viper.GetBool("CloneRewrite"),
		cloneInsecure,
	)
	proxy.ServeHTTP(w, r)
}

// ServeTargetHTTP serves the http for the Target.
// - This is unmodified from ReverseProxy.ServeHTTP except for logging
func (p *ReverseClonedProxy) ServeTargetHTTP(rw http.ResponseWriter, req *http.Request, uid uuid.UUID) (int, int64, string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered: %s\n", r)
		}
	}()

	t := time.Now()
	transport := p.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	ctx := req.Context()
	if cn, ok := rw.(http.CloseNotifier); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		notifyChan := cn.CloseNotify()
		go func() {
			select {
			case <-notifyChan:
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	outreq := new(http.Request)
	*outreq = *req // includes shallow copies of maps, but okay
	if req.ContentLength == 0 {
		outreq.Body = nil // Issue 16036: nil Body for http.Transport retries
	}
	outreq = outreq.WithContext(ctx)

	p.Director(outreq)
	outreq.Close = false

	// We are modifying the same underlying map from req (shallow
	// copied above) so we only copy it if necessary.
	copiedHeaders := false

	// Remove hop-by-hop headers listed in the "Connection" header.
	// See RFC 2616, section 14.10.
	if c := outreq.Header.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				if !copiedHeaders {
					outreq.Header = make(http.Header)
					copyHeader(outreq.Header, req.Header)
					copiedHeaders = true
				}
				outreq.Header.Del(f)
			}
		}
	}

	// Remove hop-by-hop headers to the backend. Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.
	for _, h := range hopHeaders {
		if outreq.Header.Get(h) != "" {
			if !copiedHeaders {
				outreq.Header = make(http.Header)
				copyHeader(outreq.Header, req.Header)
				copiedHeaders = true
			}
			outreq.Header.Del(h)
		}
	}

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := outreq.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		outreq.Header.Set("X-Forwarded-For", clientIP)
	}
	setCloneproxyHeader(req.Header, outreq)
	outreq.Header.Set(sideServedheader, "target (a-side)")
	xffHeader := setCloneproxyXFFHeader(outreq)

	log.WithFields(log.Fields{
		"uuid":           uid,
		"side":           "A-Side",
		"request_method": outreq.Method,
		"request_path":   outreq.URL.RequestURI(),
		"request_proto":  outreq.Proto,
		"request_host":   outreq.Host,
		//		"request_header":        outreq.Header,
		"request_contentlength": outreq.ContentLength,
	}).Debug("Proxy Request")

	res, err := transport.RoundTrip(outreq)
	if err != nil {
		log.WithFields(log.Fields{
			"uuid":          uid,
			"side":          "A-Side",
			"response_code": http.StatusBadGateway,
			"error":         err,
		}).Error("Proxy Response")
		rw.WriteHeader(http.StatusBadGateway)
		return int(http.StatusBadGateway), int64(0), ""
	}

	// Remove hop-by-hop headers listed in the
	// "Connection" header of the response.
	if c := res.Header.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				res.Header.Del(f)
			}
		}
	}

	for _, h := range hopHeaders {
		res.Header.Del(h)
	}

	copyHeader(rw.Header(), res.Header)

	// The "Trailer" header isn't included in the Transport's response,
	// at least for *http.Transport. Build it up from Trailer.
	if len(res.Trailer) > 0 {
		trailerKeys := make([]string, 0, len(res.Trailer))
		for k := range res.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		rw.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	rw.WriteHeader(res.StatusCode)
	if len(res.Trailer) > 0 {
		// Force chunking if we saw a response trailer.
		// This prevents net/http from calculating the length for short
		// bodies and adding a Content-Length.
		if fl, ok := rw.(http.Flusher); ok {
			fl.Flush()
		}
	}

	body, _ := ioutil.ReadAll(res.Body)
	p.copyResponse(rw, res.Body)
	resLength := int64(len(fmt.Sprintf("%s", body)))
	resTime := time.Since(t).Nanoseconds() / 1000000

	headersToRemove := []string{
		// xff is present for target but not in clone and must be removed to do a proper comparison
		"X-Forwarded-For: " + res.Request.Header["X-Forwarded-For"][0] + "\r\n",
	}
	if viper.GetInt("LogLevel") > 4 {
		log.WithFields(log.Fields{
			"uuid":            uid,
			"side":            "A-Side",
			"response_code":   res.StatusCode,
			"response_time":   resTime,
			"response_length": resLength,
			"response_header": res.Header,
			"response_body":   string(body),
			"cloneproxy-xff":  xffHeader,
		}).Debug("Proxy Response (loglevel)")
	} else {
		log.WithFields(log.Fields{
			"uuid":            uid,
			"side":            "A-Side",
			"response_time":   resTime,
			"response_code":   res.StatusCode,
			"response_length": resLength,
		}).Debug("Proxy Response")
	}

	sha := sha1Body(body, headersToRemove)
	fmt.Fprintf(rw, string(body))

	res.Body.Close() // close now, instead of defer, to populate res.Trailer
	copyHeader(rw.Header(), res.Trailer)
	return res.StatusCode, resLength, sha
}

// ServeCloneHTTP serves the http for the Clone
// - Handles special casing for the clone (ie. No response back to client)
func (p *ReverseClonedProxy) ServeCloneHTTP(req *http.Request, uid uuid.UUID) (int, int64, string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered: %s\n", r)
		}
	}()

	t := time.Now()
	transport := p.TransportClone
	if transport == nil {
		transport = http.DefaultTransport
	}

	outreq := new(http.Request)
	*outreq = *req // includes shallow copies of maps, but okay
	if req.ContentLength == 0 {
		outreq.Body = nil // Issue 16036: nil Body for http.Transport retries
	}

	// Hmm.   Im not an expert on how contexts & cancels are handled.
	// Im making potentially a dangerous assumption that giving the clone
	// side a new context, this wont get cancelled on a client.Done.  In essence
	// no cancellation on clone if the target & client are complete.
	outreq = outreq.WithContext(context.TODO())

	p.DirectorClone(outreq)
	outreq.Close = false

	// We are modifying the same underlying map from req (shallow
	// copied above) so we only copy it if necessary.
	copiedHeaders := false

	// Remove hop-by-hop headers listed in the "Connection" header.
	// See RFC 2616, section 14.10.
	if c := outreq.Header.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				if !copiedHeaders {
					outreq.Header = make(http.Header)
					copyHeader(outreq.Header, req.Header)
					copiedHeaders = true
				}
				outreq.Header.Del(f)
			}
		}
	}

	// Remove hop-by-hop headers to the backend. Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.
	for _, h := range hopHeaders {
		if outreq.Header.Get(h) != "" {
			if !copiedHeaders {
				outreq.Header = make(http.Header)
				copyHeader(outreq.Header, req.Header)
				copiedHeaders = true
			}
			outreq.Header.Del(h)
		}
	}

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := outreq.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		outreq.Header.Set("X-Forwarded-For", clientIP)
	}

	setCloneproxyHeader(req.Header, outreq)
	outreq.Header.Set(sideServedheader, "clone (b-side)")
	xffHeader := setCloneproxyXFFHeader(outreq)

	log.WithFields(log.Fields{
		"uuid":                  uid,
		"side":                  "B-Side",
		"request_method":        outreq.Method,
		"request_path":          outreq.URL.RequestURI(),
		"request_proto":         outreq.Proto,
		"request_host":          outreq.Host,
		"request_contentlength": outreq.ContentLength,
	}).Debug("Proxy Request")

	res, err := transport.RoundTrip(outreq)
	if err != nil {
		log.WithFields(log.Fields{
			"uuid":          uid,
			"side":          "B-Side",
			"response_code": http.StatusBadGateway,
			"error":         err,
		}).Error("Proxy Response")
		return http.StatusBadGateway, int64(0), ""
	}
	defer res.Body.Close() // ensure we dont bleed connections

	body, _ := ioutil.ReadAll(res.Body)
	resLength := int64(len(fmt.Sprintf("%s", body)))
	resTime := time.Since(t).Nanoseconds() / 1000000

	var headersToRemove []string

	if viper.GetInt("LogLevel") > 4 {
		log.WithFields(log.Fields{
			"uuid":            uid,
			"side":            "B-Side",
			"response_code":   res.StatusCode,
			"response_time":   resTime,
			"response_length": resLength,
			"response_header": res.Header,
			"response_body":   string(body),
			"cloneproxy-xff":  xffHeader,
		}).Debug("Proxy Response (Details)")
	} else {
		log.WithFields(log.Fields{
			"uuid":            uid,
			"side":            "B-Side",
			"response_code":   res.StatusCode,
			"response_time":   resTime,
			"response_length": resLength,
		}).Debug("Proxy Response")
	}

	// Remove hop-by-hop headers listed in the
	// "Connection" header of the response.
	if c := res.Header.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				res.Header.Del(f)
			}
		}
	}

	for _, h := range hopHeaders {
		res.Header.Del(h)
	}

	sha := sha1Body(body, headersToRemove)

	return res.StatusCode, resLength, sha
}

type nopCloser struct {
	io.Reader
}

func getTLSProtocol(version uint16) string {
	switch {
	case version == tls.VersionTLS10:
		return "TLS1.0"
	case version == tls.VersionTLS11:
		return "TLS1.1"
	case version == tls.VersionTLS12:
		return "TLS1.2"
	default:
		return "Unknown"
	}
}

func (nopCloser) Close() error { return nil }

// ***************************************************************************
// Handle umbrella ServeHTTP interface
// - Replicates the request
// - Call each of ServeTargetHTTP & ServeCloneHTTP asynchronously
// - Nothing else...
func (p *ReverseClonedProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered: %s\n", r)
		}
	}()

	// Normal mechanism for expvar support doesnt work with ReverseProxy
	if req.URL.Path == "/debug/vars" && req.Method == "GET" {
		expvar.Handler().ServeHTTP(rw, req)
		return
	}

	if len(viper.GetString("TLSKey")) > 0 {
		if tlsConn != nil {
			log.WithFields(log.Fields{
				"ConnectionState": tlsConn.ConnectionState(),
			}).Debug("Connection State")

			log.WithFields(log.Fields{
				"Connected with TLS Protocol": getTLSProtocol(tlsConn.ConnectionState().Version),
				"Min TLS Protocol":            viper.GetFloat64("MinVerTLS"),
			}).Debug("TLS Info")
		}
	}

	cloneURL, err := rewrite(req.URL.RequestURI())
	if err != nil {
		fmt.Println(err)
	}
	if cloneURL == nil {
		cloneURL = req.URL
	}

	makeCloneRequest, err := MatchingRule(req.URL.RequestURI())
	if err != nil {
		fmt.Println(err)
	}

	targetServed := req.Header.Get(cloneproxyHeader)
	if targetServed != "" {
		count, err := strconv.Atoi(targetServed)
		if err == nil {
			if count > viper.GetInt("MaxTotalHops") {
				log.WithFields(log.Fields{
					"cloneproxied traffic count": targetServed,
				}).Info("Cloneproxied traffic counter exceeds maximum at ", count)
				fmt.Println("Cloneproxied traffic exceed maximum at:", targetServed)
				return
			}
			if count >= viper.GetInt("MaxCloneHops") {
				// only serve a-side (target)
				makeCloneRequest = false
			}
		}
	}

	// Initialize tracking vars
	uid, _ := uuid.NewV4()
	t := time.Now()

	// Copy Body
	b1 := new(bytes.Buffer)
	b2 := new(bytes.Buffer)
	w := io.MultiWriter(b1, b2)
	io.Copy(w, req.Body)

	// Target is a pointer copy of original req with new iostream for Body
	targetReq := new(http.Request)
	*targetReq = *req
	targetReq.Body = nopCloser{b1}

	// Clone is a deep copy of original req
	cloneStatusCode := 0
	cloneContentLength := int64(0)
	cloneSHA1 := ""
	cloneRandom := rand.New(rand.NewSource(time.Now().UnixNano())).Float64() * 100

	cloneReq := &http.Request{
		Method:        req.Method,
		URL:           cloneURL,
		Proto:         req.Proto,
		ProtoMajor:    req.ProtoMajor,
		ProtoMinor:    req.ProtoMinor,
		Header:        req.Header,
		Body:          nopCloser{b2},
		Host:          req.Host,
		ContentLength: req.ContentLength,
		Close:         req.Close,
	}

	// Process Target
	targetStatusCode, targetContentLength, targetSHA1 := p.ServeTargetHTTP(rw, targetReq, uid)
	req.Body.Close()

	// Process Clone
	//    iff Target returned without server error
	//        && random number is less than percent
	duration := time.Since(t).Nanoseconds() / 1000000
	switch {
	case targetStatusCode < 500: // NON-SERVER ERROR
		if makeCloneRequest && (viper.GetFloat64("ClonePercent") == 100.0 || cloneRandom < viper.GetFloat64("ClonePercent")) {
			cloneStatusCode, cloneContentLength, cloneSHA1 = p.ServeCloneHTTP(cloneReq, uid)
			// Ultra simple timing information for total of both a & b
			duration = time.Since(t).Nanoseconds() / 1000000
		}
	case targetStatusCode >= 500: // SERVER ERROR
		totalSkipped.Add(1)
		log.WithFields(log.Fields{
			"uuid":            uid,
			"request_method":  req.Method,
			"request_path":    req.URL.RequestURI(),
			"a_response_code": targetStatusCode,
			"b_response_code": 0,
			"duration":        duration,
		}).Info("Proxy Clone Request Skipped")
		return
	}

	// Clone SERVER ERROR after processed Target
	// - This means LOST data at clone
	if makeCloneRequest && cloneStatusCode >= 500 {
		totalUnfulfilled.Add(1)
		log.WithFields(log.Fields{
			"uuid":            uid,
			"request_method":  req.Method,
			"request_path":    cloneURL,
			"a_response_code": targetStatusCode,
			"b_response_code": cloneStatusCode,
			"duration":        duration,
		}).Error("Proxy Clone Request Unfulfilled")
		return
	}

	// Clone/Target Mismatch
	// - This means disagreement between Clone & Target
	// - This could be completely ok dependent on how responses are handled
	infoSuccess := "Proxy Clone Request Skipped"
	if makeCloneRequest && cloneStatusCode > 0 {
		infoSuccess = "CloneProxy Responses Match"
	}

	if (makeCloneRequest && cloneStatusCode > 0) && ((cloneStatusCode != targetStatusCode) || (cloneSHA1 != targetSHA1) || (cloneContentLength != targetContentLength)) {
		totalMismatches.Add(1)
		log.WithFields(log.Fields{
			"uuid":              uid,
			"request_method":    req.Method,
			"request_path":      req.URL.RequestURI(),
			"a_response_code":   targetStatusCode,
			"b_response_code":   cloneStatusCode,
			"a_response_length": targetContentLength,
			"b_response_length": cloneContentLength,
			"a_sha1":            targetSHA1,
			"b_sha1":            cloneSHA1,
			"duration":          duration,
		}).Warn("CloneProxy Responses Mismatch")
	} else {
		totalMatches.Add(1)
		log.WithFields(log.Fields{
			"uuid":                  uid,
			"request_method":        req.Method,
			"request_path":          req.URL.RequestURI(),
			"request_contentlength": req.ContentLength,
			"response_code":         targetStatusCode,
			"response_length":       targetContentLength,
			"sha1":                  targetSHA1,
			"duration":              duration,
			"clone_request":         makeCloneRequest,
		}).Info(infoSuccess)
	}

	return
}

func (p *ReverseClonedProxy) copyResponse(dst io.Writer, src io.Reader) int64 {
	if p.FlushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: p.FlushInterval,
				done:    make(chan bool),
			}
			go mlw.flushLoop()
			defer mlw.stop()
			dst = mlw
		}
	}

	var buf []byte
	if p.BufferPool != nil {
		buf = p.BufferPool.Get()
	}
	written, _ := p.copyBuffer(dst, src, buf)
	if p.BufferPool != nil {
		p.BufferPool.Put(buf)
	}
	return written
}

func (p *ReverseClonedProxy) copyBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if rerr != nil && rerr != io.EOF {
			log.Errorf("util: CloneProxy read error during resp body copy: %v", rerr)
		}
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			return written, rerr
		}
	}
}

type writeFlusher interface {
	io.Writer
	http.Flusher
}

type maxLatencyWriter struct {
	dst     writeFlusher
	latency time.Duration

	mu   sync.Mutex // protects Write + Flush
	done chan bool
}

func (m *maxLatencyWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dst.Write(p)
}

func (m *maxLatencyWriter) flushLoop() {
	t := time.NewTicker(m.latency)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			if onExitFlushLoop != nil {
				onExitFlushLoop()
			}
			return
		case <-t.C:
			m.mu.Lock()
			m.dst.Flush()
			m.mu.Unlock()
		}
	}
}

func (m *maxLatencyWriter) stop() { m.done <- true }

func parseURLWithDefaults(ustr string) *url.URL {
	if ustr == "" {
		return new(url.URL)
	}
	u, err := url.ParseRequestURI(ustr)
	if err != nil {
		fmt.Printf("Error: Unable to parse url %s  (Ex.  http://localhost:9001)", ustr)
		os.Exit(1)
	}
	//if u.Port() == "" && u.Scheme == "https" {
	//	u.Host = fmt.Sprintf("%s:443", u.Host)
	//}
	//if u.Port() == "" && u.Scheme == "http" {
	//	u.Host = fmt.Sprintf("%s:80", u.Host)
	//}
	return u
}

// NewCloneProxy instantiates a NewCloneProxy.
// select a host from the passed `targets`
func NewCloneProxy(target *url.URL, targetTimeout int, targetRewrite bool, targetInsecure bool, clone *url.URL, cloneTimeout int, cloneRewrite bool, cloneInsecure bool) *ReverseClonedProxy {
	targetQuery := target.RawQuery
	cloneQuery := clone.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if target.Scheme == "https" || targetRewrite {
			req.Host = target.Host
		}
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}
	directorclone := func(req *http.Request) {
		req.URL.Scheme = clone.Scheme
		req.URL.Host = clone.Host
		req.URL.Path = singleJoiningSlash(clone.Path, req.URL.Path)
		if clone.Scheme == "https" || cloneRewrite {
			req.Host = clone.Host
		}
		if cloneQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = cloneQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = cloneQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}

	return &ReverseClonedProxy{
		Director:      director,
		DirectorClone: directorclone,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   time.Duration(time.Duration(cloneTimeout) * time.Second),
				KeepAlive: 60 * time.Second,
			}).Dial,
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 50,
			DialTLS: func(network, addr string) (net.Conn, error) {
				var err error
				tlsConn, err = tls.Dial(network, addr, tlsConfig)

				return tlsConn, err
			},
			TLSHandshakeTimeout: 5 * time.Second,
			TLSClientConfig:     tlsConfig,
		},
		TransportClone: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   time.Duration(time.Duration(cloneTimeout) * time.Second),
				KeepAlive: 60 * time.Second,
			}).Dial,
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 50,
			DialTLS: func(network, addr string) (net.Conn, error) {
				var err error
				tlsConn, err = tls.Dial(network, addr, tlsConfig)

				return tlsConn, err
			},
			TLSHandshakeTimeout: 5 * time.Second,
			TLSClientConfig:     tlsConfig,
		},
	}
}

func logStatus() {
	log.WithFields(log.Fields{
		"version":          build,
		"cli":              strings.Join(os.Args, " "),
		"totalMatches":     totalMatches.Value(),
		"totalMismatches":  totalMismatches.Value(),
		"totalUnfulfilled": totalUnfulfilled.Value(),
		"totalSkipped":     totalSkipped.Value(),
		"uptime":           time.Since(timeOrigin).String(),
	}).Warn("Cloneproxy Status")
	return
}

func increaseTCPLimits() {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		fmt.Printf("Error: Initialization (%s)\n", err)
		os.Exit(1)
	}
	rLimit.Cur = viper.GetUint64("ExpandMaxTCP")
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		fmt.Printf("Error: Initialization (%s)\n", err)
		os.Exit(1)
	}
}

func rewrite(request string) (*url.URL, error) {
	path, err := getPathFromConfig(request)
	if err != nil {
		return nil, err
	}

	_, currentPath := getConfigPaths(path)
	if currentPath["rewrite"].(bool) {
		requestToRewrite := request

		rewriteRules := currentPath["rewriterules"].(map[string]string)
		for pattern, substitution := range rewriteRules {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("error: %s is an invalid regex, not rewriting URL", pattern)
			}

			requestToRewrite = re.ReplaceAllString(requestToRewrite, substitution)
		}

		return url.Parse(requestToRewrite)
	}
	return nil, nil
}

// MatchingRule enforces the config's matching rules.
func MatchingRule(request string) (bool, error) {
	path, err := getPathFromConfig(request)
	if err != nil {
		return false, err
	}

	_, currentPath := getConfigPaths(path)

	configMatchingRule := currentPath["matchingrule"].(string)
	configCloneURL := currentPath["clone"].(string)
	if configMatchingRule != "" {
		exclude := strings.Contains(configMatchingRule, exclusionFlag)
		matchingRule := strings.TrimPrefix(configMatchingRule, exclusionFlag)
		pattern, err := regexp.Compile(matchingRule)

		if err != nil {
			return false, fmt.Errorf("error: %s is an invalid regex, not sending to %s", configMatchingRule, configCloneURL)
		}

		matches := pattern.MatchString(request)
		if (exclude && matches) || (!exclude && !matches) {
			// exclude: targetURLs matching the pattern || include: targetURLs not matching the pattern do not go to the b-side
			return false, nil
		}
	}

	return true, nil
}

func flags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Usage: "The path to the config file.",
			Value: "config.json",
		},
		cli.BoolFlag{
			Name:  "profile, p",
			Usage: "Logs the time taken to process a request (in ms). EnableRequestProfiling in the config.",
		},
		cli.IntFlag{
			Name:  "max-tcp",
			Usage: "Set the maxium TCP sockets for use. ExpandMaxTcp in the config.",
			Value: 4096,
		},
		cli.BoolFlag{
			Name:  "json",
			Usage: "Write JSON-encoded logs. JsonLogging in the config.",
		},
		cli.IntFlag{
			Name: "log-level",
			Usage: `Set the verbosity of logging, from 0 (error) to 5 (VerboseDebug). A higher level results in more logged information. LogLevel in the config.
	0=Error, 1=Warn, 2=Info, 3=Debug, 4=Verbose, 5=VerboseDeub. Set to at least 1 to be notified of mismatches.
			(0)        Error: 	Logs 5xx response codes and unfulfilled a and/or b-side requests.
			(1)         Warn:  	0 logging + logs when the a and b-side response codes do not match (may be expected).
			(2)         Info:  	1 and below logging + logs when a and b-side response code match and when the number of cloneproxy hops exceeds the specified maximum.
			(3)        Debug: 	2 and below logging + logs the request fields for a and b-side.
			(4)      Verbose:	3 and below logging + logs response fields for a and b-side.
			(5) VerboseDebug:	4 and below logging + logs response body for a and b-side.`,
			Value: 2,
		},
		cli.StringFlag{
			Name:  "log-file",
			Usage: "Where to write the logs. Set to the empty string \"\" if you don't want to write logs to disk. LogFilePath in the config.",
		},
		cli.IntFlag{
			Name:  "port",
			Usage: "The port where cloneproxy listens for requests. ListenPort in the config.",
			Value: 8888,
		},
		cli.IntFlag{
			Name:  "timeout",
			Usage: "Enforced client timeout. The number of seconds from the end of the request header read to the end of the response write. ListenTimeout in the config.",
			Value: 900,
		},
		cli.StringFlag{
			Name:  "tls-cert",
			Usage: "The path to the TLS certificate file (must also provide the TLS key). TlsCert in the config.",
		},
		cli.StringFlag{
			Name:  "tls-key",
			Usage: "The path to the TLS private key file. TlsKey in the config.",
		},
		cli.Float64Flag{
			Name:  "min-tls-ver",
			Usage: "The minimum version of TLS to support - up to TLS1.2. MinVerTls in the config.",
			Value: 1.0,
		},
		cli.IntFlag{
			Name:  "target-timeout",
			Usage: "Enforced timeout in seconds for a-side traffic. TargetTimeout in the config.",
			Value: 5,
		},
		cli.BoolFlag{
			Name:  "target-rewrite",
			Usage: "Set to rewrite the host header when proxying a-side traffic. TargetRewrite in the config.",
		},
		cli.IntFlag{
			Name:  "clone-timeout",
			Usage: "Enforced timeout in seconds for b-side traffic. CloneTimeout in the config.",
			Value: 5,
		},
		cli.BoolFlag{
			Name:  "clone-rewrite",
			Usage: "Set to rewrite the host header when proxing b-side traffic. CloneRewrite in the config.",
		},
		cli.Float64Flag{
			Name:  "clone-percent",
			Usage: "The percentage of traffic to send to b-side. ClonePercent in the config.",
			Value: 100.0,
		},
		cli.IntFlag{
			Name: "max-hops",
			Usage: `The maximum number of 'cloneproxied' requests to serve, where a 'cloneproxied' request is a request from another cloneproxy instance.
	Any 'cloneproxied' requests strictly exceeding this will be dropped. Meant to prevent cloneproxy request loops. MaxTotalHops in the config.`,
			Value: 2,
		},
		cli.IntFlag{
			Name: "max-clone-hops",
			Usage: `The maximum number of 'cloneproxied' requests to serve for the b-side. Any 'cloneproxied' requests greater than or equal to this will not serve the b-side.
	MaxCloneHops in the config.`,
			Value: 1,
		},
	}
}

func parseFlags(ctx *cli.Context) {
	for _, flagName := range ctx.GlobalFlagNames() {
		if ctx.GlobalIsSet(flagName) {
			// set for current session, but don't save
			viper.Set(flagName, ctx.GlobalGeneric(flagName))
		}
	}
}

func startServer(ctx *cli.Context) error {
	// load the config file
	configuration(ctx.GlobalString("config"))

	// global options take precedent over the config file
	parseFlags(ctx)

	log.SetOutput(os.Stdout)
	if viper.GetString("LogFilePath") != "" {
		file, err := os.OpenFile(viper.GetString("LogFilePath"), os.O_CREATE|os.O_WRONLY, 0666)
		if err == nil {
			multiWriter := io.MultiWriter(os.Stdout, file)
			log.SetOutput(multiWriter)
			defer file.Close()
		} else {
			fmt.Print("Failed to log to file, using default stderr")
		}
	}
	// Log as JSON instead of the default ASCII formatter
	if viper.GetBool("JSONLogging") {
		log.SetFormatter(&log.JSONFormatter{})
	}
	// Set appropriate logging level
	switch {
	case viper.GetInt("LogLevel") == 0:
		log.SetLevel(log.ErrorLevel)
	case viper.GetInt("LogLevel") == 1:
		log.SetLevel(log.WarnLevel)
	case viper.GetInt("LogLevel") == 2:
		log.SetLevel(log.InfoLevel)
	case viper.GetInt("LogLevel") >= 3:
		log.SetLevel(log.DebugLevel)
	}

	increaseTCPLimits()
	runtime.GOMAXPROCS(runtime.NumCPU() * 2)

	// Regular publication of status messages
	c := cron.New()
	c.AddFunc("0 0/15 * * *", logStatus)
	c.Start()

	logStatus()

	// start profiling server
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	s := &http.Server{
		Addr:         viper.GetString("ListenPort"),
		WriteTimeout: time.Duration(time.Duration(viper.GetInt("ListenTimeout")) * time.Second),
		ReadTimeout:  time.Duration(time.Duration(viper.GetInt("ListenTimeout")) * time.Second),
		Handler:      &baseHandle{},
		// TODO: Probably should add some denial of service max sizes etc...
	}
	if len(viper.GetString("TLSKey")) > 0 {
		var minVersion uint16
		switch {
		case viper.GetFloat64("MinVerTLS") == 1.1:
			minVersion = tls.VersionTLS11
		case viper.GetFloat64("MinVerTLS") == 1.2:
			minVersion = tls.VersionTLS12
		default:
			minVersion = tls.VersionTLS10
		}

		tlsConfig = &tls.Config{
			MinVersion:               minVersion,
			PreferServerCipherSuites: true,
			InsecureSkipVerify:       true,
		}

		s := &http.Server{
			Addr:         viper.GetString("ListenPort"),
			WriteTimeout: time.Duration(time.Duration(viper.GetInt("ListenTimeout")) * time.Second),
			ReadTimeout:  time.Duration(time.Duration(viper.GetInt("ListenTimeout")) * time.Second),
			Handler:      &baseHandle{},
			TLSConfig:    tlsConfig,
		}

		log.Fatal(s.ListenAndServeTLS(viper.GetString("TLSCert"), viper.GetString("TLSKey")))
	} else {
		log.Fatal(s.ListenAndServe())
	}

	return nil
}

func main() {
	app := cli.NewApp()
	app.Name = "cloneproxy"
	app.Usage = "A reverse proxy with a forking of traffic to a clone."
	app.Description = `You can proxy traffic to production & staging simultaneously.
	 This can be used for development/testing/benchmarking, it can
	 also be used to replicate traffic while moving across clouds.`
	app.Version = fmt.Sprintf("v%v-%v build %v %v", VERSION, minversion, build, goVersion)
	app.Flags = flags()

	// Begin actual main function
	app.Commands = []cli.Command{
		cli.Command{
			Name:   "run",
			Usage:  "start cloneproxy",
			Action: startServer,
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
