package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
)

type Proxy struct {
	URL      string
	Username string
	Password string
}

func (p Proxy) HasAuthorizationCredentials() bool {
	return p.Username != "" && p.Password != ""
}

func (p Proxy) BasicAuthorizationHeader() string {
	auth := fmt.Sprintf("%s:%s", p.Username, p.Password)
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
	return "Basic " + encodedAuth
}

func (p Proxy) HttpTransport() http.Transport {
	proxyURLFunc := func(r *http.Request) (*url.URL, error) {
		return url.Parse(p.URL)
	}
	transport := http.Transport{
		Proxy: proxyURLFunc,
	}
	if p.HasAuthorizationCredentials() {
		transport.ProxyConnectHeader = http.Header{}
		transport.ProxyConnectHeader.Add("Proxy-Authorization", p.BasicAuthorizationHeader())
	}
	return transport
}

// func createHttpClientWithProxy(proxy *Proxy) *http.Client {
// 	var basicAuth string

// 	transport := &http.Transport{
// 		Proxy: getProxyURL,
// 		TLSClientConfig: &tls.Config{
// 			InsecureSkipVerify: true,
// 		},
// 		MaxIdleConns:       100,
// 		IdleConnTimeout:    90 * time.Second,
// 		DisableCompression: true,
// 	}

// 	if proxy.Username != "" {
// 		auth := fmt.Sprintf("%s:%s", proxy.Username, proxy.Password)
// 		basicAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
// 		transport.ProxyConnectHeader = http.Header{}
// 		transport.ProxyConnectHeader.Add("Proxy-Authorization", basicAuth)
// 	}

// 	httpClient := &http.Client{
// 		Transport: transport,
// 		Timeout:   timeout,
// 	}
// 	jar, err := cookiejar.New(nil)
// 	if err != nil {
// 		panic(fmt.Errorf("error creaking cookie jar: %s", err.Error()))
// 	} else {
// 		httpClient.Jar = jar
// 	}

// 	return httpClient, proxyUrlStr, basicAuth
// }
