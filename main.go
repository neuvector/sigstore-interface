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
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/signature"
	sig "github.com/sigstore/cosign/v2/pkg/signature"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/tuf"
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

func main() {
	config, err := loadConfiguration()
	if err != nil {
		log.Fatalf("ERROR: error loading config: %s", err.Error())
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
		fmt.Printf("checking root of trust: %s\n", rootOfTrust.Name)
		satisfiedVerifiers, err := verify(imageDigestHash, rootOfTrust, signatures)
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
	configFilePath := flag.String("config-file", "", "path to the config file with target image digest, root of trust, signature, and verifier data")
	flag.Parse()
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

func verify(imgDigest v1.Hash, rootOfTrust RootOfTrust, sigs []oci.Signature) (satisfiedVerifiers []string, err error) {
	ctx := context.Background()
	cosignOptions := cosign.CheckOpts{ClaimVerifier: cosign.SimpleClaimVerifier}
	err = setRootOfTrustCosignOptions(&cosignOptions, rootOfTrust, ctx)
	if err != nil {
		return satisfiedVerifiers, fmt.Errorf("could not set root of trust %s cosign check options: %s", rootOfTrust.Name, err.Error())
	}
	for _, verifier := range rootOfTrust.Verifiers {
		fmt.Printf("checking verifier %s\n", verifier.Name)
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

func setRootOfTrustCosignOptions(cosignOptions *cosign.CheckOpts, rootOfTrust RootOfTrust, ctx context.Context) (err error) {
	// rekor pub keys
	if rootOfTrust.RekorPublicKey != "" {
		publicKeyCollection := cosign.NewTrustedTransparencyLogPubKeys()
		if err := publicKeyCollection.AddTransparencyLogPubKey([]byte(rootOfTrust.RekorPublicKey), tuf.Active); err != nil {
			return fmt.Errorf("could not add custom rekor public key to collection: %w", err)
		}
		cosignOptions.RekorPubKeys = &publicKeyCollection
	} else {
		cosignOptions.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
		if err != nil {
			return fmt.Errorf("could not get default rekor public key: %w", err)
		}
	}
	// root certificate(s)
	if rootOfTrust.RootCert != "" {
		selfSigned := func(cert *x509.Certificate) bool {
			return bytes.Equal(cert.RawSubject, cert.RawIssuer)
		}
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
		cosignOptions.RootCerts, err = fulcio.GetRoots()
		if err != nil {
			return fmt.Errorf("could not fetch default fulcio root certificate(s): %s", err.Error())
		}
		cosignOptions.IntermediateCerts, err = fulcio.GetIntermediates()
		if err != nil {
			return fmt.Errorf("could not fetch default fulcio intermediate certificate(s): %s", err.Error())
		}
	}
	// sct pub keys
	if rootOfTrust.SCTPublicKey != "" {
		sctPubKeyCollection := cosign.NewTrustedTransparencyLogPubKeys()
		if err := sctPubKeyCollection.AddTransparencyLogPubKey([]byte(rootOfTrust.SCTPublicKey), tuf.Active); err != nil {
			return fmt.Errorf("could not add custom sct public key to collection: %w", err)
		}
		cosignOptions.CTLogPubKeys = &sctPubKeyCollection
	} else {
		cosignOptions.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return fmt.Errorf("error retrieving default CT log public keys: %s", err.Error())
		}
	}
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
