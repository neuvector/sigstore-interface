package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/signature"
	sig "github.com/sigstore/cosign/v2/pkg/signature"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigtuf "github.com/sigstore/sigstore/pkg/tuf"
)

type Configuration struct {
	ImageDigest   string        `json:"ImageDigest"`
	RootsOfTrust  []RootOfTrust `json:"RootsOfTrust"`
	SignatureData SignatureData `json:"SignatureData"`
}

type RootOfTrust struct {
	Name           string     `json:"Name"`
	RekorPublicKey string     `json:"RekorPublicKey"`
	RootCert       string     `json:"RootCert"`
	SCTPublicKey   string     `json:"SCTPublicKey"`
	Verifiers      []Verifier `json:"Verifiers"`
}

func (r *RootOfTrust) IsPublic() bool {
	return r.RekorPublicKey == "" && r.RootCert == "" && r.SCTPublicKey == ""
}

type Verifier struct {
	Name           string                 `json:"Name"`
	Type           string                 `json:"Type"`
	KeyPairOptions VerifierKeyPairOptions `json:"KeyPairOptions"`
	KeylessOptions VerifierKeylessOptions `json:"KeylessOptions"`
}

type VerifierKeyPairOptions struct {
	PublicKey string `json:"PublicKey"`
}

type VerifierKeylessOptions struct {
	CertIssuer  string `json:"CertIssuer"`
	CertSubject string `json:"CertSubject"`
}

type SignatureData struct {
	Manifest string            `json:"Manifest"`
	Payloads map[string]string `json:"Payloads"`
}

var configFilePath = flag.String("config-file", "", "path to the config file with target image digest, root of trust, signature, and verifier data")

var proxyURL = flag.String("proxy-url", "", "")
var proxyHasCredentials = flag.Bool("proxy-has-credentials", false, "")

func getProxyDetails() (Proxy, error) {
	proxy := Proxy{URL: *proxyURL}
	if *proxyURL != "" && *proxyHasCredentials {
		fmt.Println("getting proxy credential details")
		stdinCredentials, err := os.ReadFile(os.Stdin.Name())
		if err != nil {
			return Proxy{}, fmt.Errorf("error when reading credentials, could not read stdin: %s", err.Error())
		}
		splitCredentials := strings.Split(string(stdinCredentials), ":")
		if len(splitCredentials) != 2 {
			return Proxy{}, fmt.Errorf("error when reading credentials, invalid format, credential string should have single colon (USERNAME:PASSWORD)")
		}
		proxy.Username = splitCredentials[0]
		proxy.Password = splitCredentials[1]
	}
	return proxy, nil
}

func main() {
	flag.Parse()
	config, err := loadConfiguration()
	if err != nil {
		log.Fatalf("ERROR: error loading config: %s", err.Error())
	}

	proxy, err := getProxyDetails()
	if err != nil {
		log.Fatalf("ERROR: error when getting proxy details: %s", err.Error())
	}

	imageDigestHash, err := v1.NewHash(config.ImageDigest)
	if err != nil {
		log.Fatalf("ERROR: error hashing image digest: %s", err.Error())
	}

	signatures, err := generateCosignSignatureObjects(config.SignatureData)
	if err != nil {
		log.Fatalf("ERROR: error generating objects for signature data: %s", err.Error())
	}

	allSatisfiedVerifiers := []string{}
	for _, rootOfTrust := range config.RootsOfTrust {
		fmt.Printf("\n>>>> checking root of trust: %s\n", rootOfTrust.Name)
		satisfiedVerifiers, err := verify(imageDigestHash, rootOfTrust, signatures, proxy)
		if err != nil {
			// line with prefix "ERROR: " is recognized by scanner for error encounted when verifying against a verifier
			fmt.Printf("ERROR: %s\n", err.Error())
		} else if len(satisfiedVerifiers) > 0 {
			allSatisfiedVerifiers = append(allSatisfiedVerifiers, satisfiedVerifiers...)
		}
	}

	// line with prefix "Satisfied verifiers: " is recognized by scanner for all the satisfied verifiers separated by ", "
	fmt.Printf("Satisfied verifiers: %s\n", strings.Join(allSatisfiedVerifiers, ", "))
}

func loadConfiguration() (config Configuration, err error) {
	if *configFilePath == "" {
		return config, errors.New("must provide --config-file flag")
	}
	configFile, err := os.ReadFile(*configFilePath)
	if err != nil {
		return config, fmt.Errorf("could not read config file: %s", err.Error())
	}
	err = json.Unmarshal(configFile, &config)
	if err != nil {
		return config, fmt.Errorf("could not unmarshal config file: %s", err.Error())
	}
	return config, nil
}

func generateCosignSignatureObjects(sigData SignatureData) ([]oci.Signature, error) {
	parsedManifest, err := v1.ParseManifest(bytes.NewReader([]byte(sigData.Manifest)))
	if err != nil {
		return nil, fmt.Errorf("could not parse manifest from signatures data: %s", err.Error())
	}
	signatures := []oci.Signature{}
	for _, manifestLayer := range parsedManifest.Layers {
		layerDigest := manifestLayer.Digest.String()
		payloadLayer := static.NewLayer([]byte(sigData.Payloads[layerDigest]), parsedManifest.MediaType)
		signatures = append(signatures, signature.New(payloadLayer, manifestLayer))
	}
	return signatures, nil
}

func verify(imgDigest v1.Hash, rootOfTrust RootOfTrust, sigs []oci.Signature, proxy Proxy) (satisfiedVerifiers []string, err error) {
	ctx := context.Background()
	cosignOptions := cosign.CheckOpts{ClaimVerifier: cosign.SimpleClaimVerifier}
	err = setRootOfTrustCosignOptions(&cosignOptions, rootOfTrust, proxy, ctx)
	if err != nil {
		return satisfiedVerifiers, fmt.Errorf("could not set root of trust %s cosign check options: %s", rootOfTrust.Name, err.Error())
	}
	for _, verifier := range rootOfTrust.Verifiers {
		cosignOptions.SigVerifier = nil
		cosignOptions.Identities = nil
		fmt.Printf(">> checking verifier %s\n", verifier.Name)
		err = setVerifierCosignOptions(&cosignOptions, verifier, rootOfTrust, ctx)
		if err != nil {
			fmt.Printf("ERROR: %s\n", err.Error())
		} else {
			for i, signature := range sigs {
				fmt.Printf("verifying signature %d\n", i)
				_, err := cosign.VerifyImageSignature(ctx, signature, imgDigest, &cosignOptions)
				if err != nil {
					// the image is not signed by this verifier
					fmt.Printf("signature not verified: %s\n", err.Error())
				} else {
					fmt.Printf("signature %d satisfies verifier %s\n", i, verifier.Name)
					satisfiedVerifiers = append(satisfiedVerifiers, fmt.Sprintf("%s/%s", rootOfTrust.Name, verifier.Name))
					break
				}
			}
		}
	}
	return satisfiedVerifiers, nil
}

func setRootOfTrustCosignOptions(cosignOptions *cosign.CheckOpts, rootOfTrust RootOfTrust, proxy Proxy, ctx context.Context) (err error) {
	// rekor public keys
	rekorKeyCollection := cosign.NewTrustedTransparencyLogPubKeys()
	if rootOfTrust.RekorPublicKey == "" {
		rekorKeyTargets, err := GetTargets(sigtuf.Rekor, proxy)
		if err != nil {
			return fmt.Errorf("could not retrieve rekor tuf targets: %s", err.Error())
		}
		for _, rekorKeyTarget := range rekorKeyTargets {
			if err := rekorKeyCollection.AddTransparencyLogPubKey(rekorKeyTarget.Target, rekorKeyTarget.Status); err != nil {
				return fmt.Errorf("could not add public root of trust rekor public key to collection: %w", err)
			}
		}
	} else {
		if err := rekorKeyCollection.AddTransparencyLogPubKey([]byte(rootOfTrust.RekorPublicKey), sigtuf.Active); err != nil {
			return fmt.Errorf("could not add custom root of trust rekor public key to collection: %w", err)
		}
	}
	cosignOptions.RekorPubKeys = &rekorKeyCollection

	// root & intermediate certificates
	selfSigned := func(cert *x509.Certificate) bool {
		return bytes.Equal(cert.RawSubject, cert.RawIssuer)
	}
	if rootOfTrust.RootCert != "" {
		rootPool := x509.NewCertPool()
		var intermediatePool *x509.CertPool // should be nil if no intermediate certs are found
		certs, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(rootOfTrust.RootCert))
		if err != nil {
			return fmt.Errorf("error unmarshalling provided root certificate(s): %w", err)
		}
		for _, cert := range certs {
			if selfSigned(cert) {
				rootPool.AddCert(cert)
			} else {
				if intermediatePool == nil {
					intermediatePool = x509.NewCertPool()
				}
				intermediatePool.AddCert(cert)
			}
		}
		cosignOptions.RootCerts = rootPool
		cosignOptions.IntermediateCerts = intermediatePool
	} else {
		targetCertificates, err := GetTargets(sigtuf.Fulcio, proxy)
		// certificates, err := GetPublicRootOfTrustFulcioCertificates(proxy)
		if err != nil {
			return fmt.Errorf("could not retrieve public root of trust fulcio certificates: %s", err.Error())
		}
		rootPool := x509.NewCertPool()
		var intermediatePool *x509.CertPool // should be nil if no intermediate certs are found
		for _, targetCertificate := range targetCertificates {
			certs, err := cryptoutils.UnmarshalCertificatesFromPEM(targetCertificate.Target)
			if err != nil {
				continue
			}
			for _, cert := range certs {
				if selfSigned(cert) {
					rootPool.AddCert(cert)
				} else {
					if intermediatePool == nil {
						intermediatePool = x509.NewCertPool()
					}
					intermediatePool.AddCert(cert)
				}
			}
		}
		cosignOptions.RootCerts = rootPool
		cosignOptions.IntermediateCerts = intermediatePool
	}

	// sct public keys
	sctKeyCollection := cosign.NewTrustedTransparencyLogPubKeys()
	if rootOfTrust.SCTPublicKey == "" {
		sctKeyTargets, err := GetTargets(sigtuf.CTFE, proxy)
		if err != nil {
			return fmt.Errorf("could not retrieve ctfe tuf targets: %s", err.Error())
		}
		for _, sctKeyTarget := range sctKeyTargets {
			if err := sctKeyCollection.AddTransparencyLogPubKey(sctKeyTarget.Target, sctKeyTarget.Status); err != nil {
				return fmt.Errorf("could not add public root of trust sct public key to collection: %w", err)
			}
		}
	} else {
		if err := sctKeyCollection.AddTransparencyLogPubKey([]byte(rootOfTrust.SCTPublicKey), sigtuf.Active); err != nil {
			return fmt.Errorf("could not add custom root of trust sct public key to collection: %w", err)
		}
	}
	cosignOptions.CTLogPubKeys = &sctKeyCollection

	return nil
}

func setVerifierCosignOptions(cosignOptions *cosign.CheckOpts, verifier Verifier, rootOfTrust RootOfTrust, ctx context.Context) (err error) {
	switch verifier.Type {
	case "keypair":
		cosignOptions.SigVerifier, err = sig.LoadPublicKeyRaw([]byte(verifier.KeyPairOptions.PublicKey), crypto.SHA256)
		if err != nil {
			return fmt.Errorf("could not load PEM encoded public key of verifier %s under %s: %s", verifier.Name, rootOfTrust.Name, err.Error())
		}
	case "keyless":
		cosignOptions.Identities = []cosign.Identity{
			{
				Issuer:  verifier.KeylessOptions.CertIssuer,
				Subject: verifier.KeylessOptions.CertSubject,
			},
		}
	default:
		// verifier.Type must be "keypair" or "keyless"
		return fmt.Errorf("invalid verification type in config file: %s", verifier.Type)
	}
	if !rootOfTrust.IsPublic() {
		if rootOfTrust.RekorPublicKey == "" {
			cosignOptions.IgnoreTlog = true
		}
		if rootOfTrust.SCTPublicKey == "" {
			cosignOptions.IgnoreSCT = true
		}
	}
	return nil
}
