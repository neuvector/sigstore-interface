package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	sigtuf "github.com/sigstore/sigstore/pkg/tuf"
	tufclient "github.com/theupdateframework/go-tuf/client"
)

var globalBuffer bytes.Buffer

type inMemoryDest struct{}

func (d inMemoryDest) Write(p []byte) (n int, err error) {
	return globalBuffer.Write(p)
}

func (d inMemoryDest) Delete() error {
	panic("inMemoryDest delete function should not run")
}

func GetTargets(targetname string, usage sigtuf.UsageKind, proxy Proxy) ([]sigtuf.TargetFile, error) {
	// client initialization
	defer globalBuffer.Reset()
	var httpClient *http.Client
	if proxy.URL != "" {
		transport := proxy.HttpTransport()
		httpClient = &http.Client{Transport: &transport}
	}
	remoteStore, err := tufclient.HTTPRemoteStore(sigtuf.DefaultRemoteRoot, nil, httpClient)
	if err != nil {
		return nil, fmt.Errorf("could not create remote store object: %s", err.Error())
	}
	tufClient := tufclient.NewClient(tufclient.MemoryLocalStore(), remoteStore)
	tufClient.Init([]byte(SigstoreTUFRootJSON))
	err = tufClient.UpdateRoots()
	if err != nil {
		return nil, fmt.Errorf("error updating tuf client roots: %s", err.Error())
	}
	_, err = tufClient.Update()
	if err != nil {
		return nil, fmt.Errorf("error updating tuf client metadata: %s", err.Error())
	}

	// target retrieval
	type customMetadata struct {
		Usage  sigtuf.UsageKind  `json:"usage"`
		Status sigtuf.StatusKind `json:"status"`
	}

	type sigstoreCustomMetadata struct {
		Sigstore customMetadata `json:"sigstore"`
	}

	targets, err := tufClient.Targets()
	if err != nil {
		return nil, fmt.Errorf("error getting targets: %w", err)
	}
	var matchedTargets []sigtuf.TargetFile
	for name, targetMeta := range targets {
		// Skip any targets that do not include custom metadata.
		if targetMeta.Custom == nil {
			continue
		}
		var scm sigstoreCustomMetadata
		err := json.Unmarshal(*targetMeta.Custom, &scm)
		if err != nil {
			fmt.Fprintf(os.Stderr, "**Warning** Custom metadata not configured properly for target %s, skipping target\n", name)
			continue
		}
		if scm.Sigstore.Usage == usage {
			fmt.Printf("matched usage: %s\n", name)
			dest := inMemoryDest{}
			err = tufClient.Download(name, dest)
			if err != nil {
				panic(fmt.Errorf("error downloading target: %s", err.Error()))
			}
			matchedTargets = append(matchedTargets, sigtuf.TargetFile{Target: globalBuffer.Bytes(), Status: scm.Sigstore.Status})
			globalBuffer.Reset()
		}
	}
	return matchedTargets, nil
}

func GetPublicRootOfTrustRekorKeys(proxy Proxy) ([][]byte, error) {
	var rekorKeys [][]byte
	targets, err := GetTargets("", sigtuf.Rekor, proxy)
	if err != nil {
		return nil, fmt.Errorf("error getting rekor targets: %s", err.Error())
	}
	for _, t := range targets {
		rekorKeys = append(rekorKeys, t.Target)
	}
	return rekorKeys, nil
}

func GetPublicRootOfTrustSCTKeys(proxy Proxy) ([][]byte, error) {
	var sctKeys [][]byte
	targets, err := GetTargets("", sigtuf.CTFE, proxy)
	if err != nil {
		return nil, fmt.Errorf("error getting ctfe targets: %s", err.Error())
	}
	for _, t := range targets {
		sctKeys = append(sctKeys, t.Target)
	}
	return sctKeys, nil
}

// func GetPublicInstanceRootOfTrustTarget(targetName string, proxy Proxy) ([]byte, error) {
// 	defer globalBuffer.Reset()
// 	var httpClient *http.Client
// 	if proxy.URL != "" {
// 		transport := proxy.HttpTransport()
// 		httpClient = &http.Client{Transport: &transport}
// 	}
// 	remoteStore, err := tufclient.HTTPRemoteStore(tuf.DefaultRemoteRoot, nil, httpClient)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not create remote store object: %s", err.Error())
// 	}
// 	tufClient := tufclient.NewClient(tufclient.MemoryLocalStore(), remoteStore)
// 	tufClient.Init([]byte(SigstoreTUFRootJSON))
// 	err = tufClient.UpdateRoots()
// 	if err != nil {
// 		return nil, fmt.Errorf("error updating tuf client roots: %s", err.Error())
// 	}
// 	_, err = tufClient.Update()
// 	if err != nil {
// 		return nil, fmt.Errorf("error updating tuf client metadata: %s", err.Error())
// 	}
// 	dest := inMemoryDest{}
// 	err = tufClient.Download(targetName, dest)
// 	if err != nil {
// 		panic(fmt.Errorf("error downloading roots: %s", err.Error()))
// 	}
// 	return globalBuffer.Bytes(), nil
// }
