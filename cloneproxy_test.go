package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"reflect"
	"testing"

	"github.com/spf13/viper"
)

var (
	configFilename = "configTest.json"
)

func populateConfig() {
	viper.SetConfigType("json")
	viper.SetConfigFile(configFilename)

	config, err := ioutil.ReadFile(configFilename)
	if err != nil {
		log.Fatalf("Error, missing %s file", configFilename)
	}

	viper.ReadConfig(bytes.NewBuffer(config))
}

func jsonToString(obj map[string]interface{}) string {
	bytes, _ := json.Marshal(obj)
	return string(bytes)
}

func updatePathsInConfig(route string, keyToUpdate string, valueToUse interface{}) map[string]interface{} {
	// get the route to modify
	var configPaths, configRoutePath = getConfigPaths(route)

	// update the config
	configRoutePath[keyToUpdate] = valueToUse
	configPaths[route] = configRoutePath
	viper.Set("Paths", configPaths)

	return configRoutePath
}

func testRewrite(t *testing.T, route string, expected interface{}, rewriteRules map[string]string, expectingError bool) {
	updatePathsInConfig(route, "rewriterules", rewriteRules)

	// rewrite
	fmt.Printf("\tTesting rewrite Rules: '%v'... ", rewriteRules)
	if cloneURL, err := rewrite(route); err != nil {
		if !expectingError {
			t.Error(err)
		} else {
			fmt.Println("passed")
		}
	} else if cloneURL.Path != expected {
		t.Error("expected", expected, "got", cloneURL.Path)
	} else {
		fmt.Println("passed")
	}
}

func TestRewrite(t *testing.T) {
	fmt.Println("========TESTING REWRITE========")
	populateConfig()

	// test valid regex
	fmt.Println("Testing regex...")

	// update the config with a new substitution
	inputPath := "/project/5AF308SDF093JF02/queues/wrong_queue_name"
	expectedPath := "/project/5AF308SDF093JF02/queues/right_queue_name"
	rewriteRules := map[string]string{"wrong_queue_name": "right_queue_name"}
	testRewrite(t, inputPath, expectedPath, rewriteRules, false)

	rewriteRules = map[string]string{"wrong_queue_name": ""}
	expectedPath = "/project/5AF308SDF093JF02/queues/"
	testRewrite(t, inputPath, expectedPath, rewriteRules, false)

	rewriteRules = map[string]string{"/[a-z]+_[a-z]+_[a-z]+$": "/right_queue_name"}
	expectedPath = "/project/5AF308SDF093JF02/queues/right_queue_name"
	testRewrite(t, inputPath, expectedPath, rewriteRules, false)

	rewriteRules = map[string]string{"/project/[A-Z0-9]{16}/queues/wrong_queue_name": "/project/6AF308SDF093JF03/queues/right_queue_name"}
	expectedPath = "/project/6AF308SDF093JF03/queues/right_queue_name"
	testRewrite(t, inputPath, expectedPath, rewriteRules, false)

	// test invalid regex
	fmt.Println("\nTesting invalid regex...")

	rewriteRules = map[string]string{"/queues/[0-9]++": "/right_queue_name"}
	testRewrite(t, inputPath, nil, rewriteRules, true)

	// testing zero-valued map
	rewriteRules = map[string]string{}
	expectedPath = "/project/5AF308SDF093JF02/queues/wrong_queue_name"
	testRewrite(t, inputPath, expectedPath, rewriteRules, false)

	fmt.Println()
}

func testMatchingRule(t *testing.T, route string, matchingRule string, expected bool, expectingError bool) {
	updatePathsInConfig(route, "matchingrule", matchingRule)

	if makeCloneReq, err := MatchingRule(route); err != nil {
		if !expectingError {
			t.Error(err)
		} else {
			fmt.Println("passed")
		}
	} else if makeCloneReq != expected {
		t.Error("expected", expected, "got", makeCloneReq)
	} else {
		fmt.Println("passed")
	}
}

func TestMatchingRule(t *testing.T) {
	fmt.Println("========TESTING MATCHINGRULE========")

	populateConfig()
	var route = "http://localhost:8081"

	fmt.Print("Testing inclusion rule... ")
	testMatchingRule(t, route, "localhost", true, false)

	fmt.Print("Testing exclusion rule... ")
	testMatchingRule(t, route, "!localhost", false, false)

	fmt.Print("Testing no rule... ")
	testMatchingRule(t, route, "", true, false)

	fmt.Print("Testing invalid rule... ")
	testMatchingRule(t, route, "localhost:[0-9]++", false, true)

	fmt.Println()
}

var counter = struct {
	target int
	clone  int
}{target: 0, clone: 0}

func serverA(w http.ResponseWriter, req *http.Request) {
	dump, err := httputil.DumpRequest(req, false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(w, "%s", dump)
	counter.target++
	fmt.Printf("---> %s %s %s %s\n", "8080", req.Method, req.URL.String(), req.UserAgent())
}

func serverB(w http.ResponseWriter, req *http.Request) {
	dump, err := httputil.DumpRequest(req, false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(w, "%s", dump)
	counter.clone++

	fmt.Printf("---> %s %s %s %s\n", "8081", req.Method, req.URL.String(), req.UserAgent())
}

func CloneProxy(listenPort string, path string) http.Handler {
	var _, configRoutePath = getConfigPaths(path)

	targetURL := parseURLWithDefaults(configRoutePath["target"].(string))
	cloneURL := parseURLWithDefaults(configRoutePath["clone"].(string))

	if listenPort != "" {
		viper.Set("ListenPort", listenPort)
	}

	return NewCloneProxy(
		targetURL,
		viper.GetInt("TargetTimeout"),
		viper.GetBool("TargetRewrite"),
		configRoutePath["targetinsecure"].(bool),
		cloneURL,
		viper.GetInt("CloneTimeout"),
		viper.GetBool("CloneRewrite"),
		configRoutePath["cloneinsecure"].(bool),
	)
}

func makeReq(method, url string, body io.Reader) *http.Request {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		fmt.Println(err)
	}
	return req
}

func TestCloneProxy(t *testing.T) {
	fmt.Println("========TESTING CLONEPROXY========")
	populateConfig()
	viper.Set("ClonePercent", 100.0)

	serverTarget := http.NewServeMux()
	serverTarget.HandleFunc("/", serverA)

	serverClone := http.NewServeMux()
	serverClone.HandleFunc("/", serverB)

	go func() {
		http.ListenAndServe("localhost:8080", serverTarget)
	}()
	go func() {
		http.ListenAndServe("localhost:8081", serverClone)
	}()

	targetRequests := 4
	cloneRequests := 2
	configurations := []struct {
		rewriteRules []string
		matchingRule string
	}{
		{matchingRule: "/"},
		{matchingRule: "!/"},
	}

	testPath := "/test"
	for _, configuration := range configurations {
		t.Run("Testing configurations...", func(tst *testing.T) {
			updatePathsInConfig(testPath, "matchingrule", configuration.matchingRule)

			ts := httptest.NewServer(CloneProxy("", testPath))
			defer ts.Close()

			tests := []struct {
				name string
				req  *http.Request
			}{
				{name: "Testing GET with MatchingRule " + configuration.matchingRule, req: makeReq("GET", ts.URL+testPath, nil)},
				{name: "Testing POST with MatchingRule " + configuration.matchingRule, req: makeReq("POST", ts.URL+testPath, nil)},
			}

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					fmt.Println(test.name)

					res, err := http.DefaultClient.Do(test.req)
					if err != nil {
						t.Error(err)
					}
					defer res.Body.Close()
					if _, err := ioutil.ReadAll(res.Body); err != nil {
						// unexpected EOF, known issue with go
					}
				})
			}
		})
	}

	// make sure counts are correct
	// requests are always sent to target (we make 4 requests)
	// we should only be making 2 requests to clone
	if counter.target != targetRequests || counter.clone != cloneRequests {
		t.Errorf("expected %d requests to target and %d requests to clone got %d target and %d clone\n", targetRequests, cloneRequests, counter.target, counter.clone)
	}
	fmt.Println()
}

func TestHops(t *testing.T) {
	// tests MaxCloneHops -- the maximum number of b-side requests to serve
	// this also implicitly tests MaxTotalHops -- if this wasn't working, this test would never end
	fmt.Println("========TESTING CLONEPROXY HOPS========")
	populateConfig()
	viper.Set("ClonePercent", 100.0)
	path := "/hops"

	serverTarget := http.NewServeMux()
	serverTarget.HandleFunc("/", serverA)
	go func() {
		http.ListenAndServe("localhost:8080", serverTarget)
	}()

	listener, err := net.Listen("tcp", "127.0.0.1:8888")
	if err != nil {
		t.Error(err)
	}

	cloneproxy := httptest.NewUnstartedServer(CloneProxy("", path))
	cloneproxy.Listener.Close()
	cloneproxy.Listener = listener

	cloneproxy.Start()
	defer cloneproxy.Close()

	totalCloneHops := 1
	counter.target = 0
	req := makeReq("GET", cloneproxy.URL+path, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer res.Body.Close()

	// we should only be making totalCloneHops number of requests to the b-side
	if counter.target != totalCloneHops {
		t.Errorf("expected %d hops, did %d instead\n", totalCloneHops, counter.target)
	}
	fmt.Println()
}

func TestServicePing(t *testing.T) {
	fmt.Println("========TESTING /service/ping========")

	populateConfig()
	servicePing := "/service/ping"

	cloneproxy := httptest.NewServer(&baseHandle{})

	req := makeReq("GET", cloneproxy.URL+servicePing, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}

	response := map[string]string{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		t.Error(err)
	}

	expected := map[string]string{"msg": "imok"}
	if eq := reflect.DeepEqual(response, expected); !eq {
		t.Errorf("server returned %v when it should have returned %v", response, expected)
	}

	fmt.Println("passed")
	fmt.Println()
}

func TestMissingPathFromConfig(t *testing.T) {
	fmt.Println("========TESTING Missing Path From Config Request========")

	populateConfig()
	endpoint := "/notinconfig"

	cloneproxy := httptest.NewServer(&baseHandle{})

	req := makeReq("GET", cloneproxy.URL+endpoint, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}

	response := map[string]string{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		t.Error(err)
	}

	if res.StatusCode != http.StatusNotFound {
		t.Errorf("expected response status code %v to be %v", res.StatusCode, http.StatusNotFound)
	}

	expectedResponseBody := map[string]string{"error": fmt.Sprintf("unable to process request: no path contains '%s' in the config file", endpoint)}
	if eq := reflect.DeepEqual(response, expectedResponseBody); !eq {
		t.Errorf("server returned %v when it should have returned %v", response, expectedResponseBody)
	}

	fmt.Println("passed")
	fmt.Println()
}

func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}
