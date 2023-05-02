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
	RootOfTrust   RootOfTrust   `json:"RootOfTrust"`
	Verifiers     []Verifier    `json:"Verifiers"`
	SignatureData SignatureData `json:"SignatureData"`
}

type RootOfTrust struct {
	RekorPublicKey string `json:"RekorPublicKey"`
	RootCert       string `json:"RootCert"`
	SCTPublicKey   string `json:"SCTPublicKey"`
}

type Verifier struct {
	Name           string                 `json:"Name"`
	Type           string                 `json:"Type"`
	IgnoreTLog     bool                   `json:"IgnoreTLog"`
	IgnoreSCT      bool                   `json:"IgnoreSCT"`
	KeyPairOptions KeyPairVerifierOptions `json:"KeyPairOptions"`
	KeylessOptions KeylessVerifierOptions `json:"KeylessOptions"`
}

type KeyPairVerifierOptions struct {
	PublicKey string `json:"PublicKey"`
}

type KeylessVerifierOptions struct {
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
		log.Fatalf("error loading config: %s", err.Error())
	}

	imageDigestHash, err := v1.NewHash(config.ImageDigest)
	if err != nil {
		log.Fatalf("error hashing image digest: %s", err.Error())
	}

	signatures, err := generateCosignSignatureObjects(config.SignatureData)
	if err != nil {
		log.Fatalf("error generating objects for signature data: %s", err.Error())
	}

	satisfiedVerifiers, err := verify(imageDigestHash, config, signatures)
	if err != nil {
		log.Fatalf("error verifying signatures: %s", err.Error())
	}

	fmt.Println("satisfied verifiers")
	fmt.Println(satisfiedVerifiers)
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

func verify(imgDigest v1.Hash, config Configuration, sigs []oci.Signature) (satisfiedVerifiers []string, err error) {
	ctx := context.Background()
	cosignOptions := cosign.CheckOpts{ClaimVerifier: cosign.SimpleClaimVerifier}
	err = setRootOfTrustCosignOptions(&cosignOptions, config.RootOfTrust, ctx)
	if err != nil {
		return satisfiedVerifiers, fmt.Errorf("could not set root of trust cosign check options: %s", err.Error())
	}
	for _, verifier := range config.Verifiers {
		fmt.Printf("checking verifier %s\n", verifier.Name)
		err = setVerifierCosignOptions(&cosignOptions, verifier, ctx)
		if err != nil {
			return satisfiedVerifiers, fmt.Errorf("could not set cosign options for verifier %s: %s", verifier.Name, err.Error())
		}
		for i, signature := range sigs {
			fmt.Printf("verifying signature %d\n", i)
			_, err := cosign.VerifyImageSignature(ctx, signature, imgDigest, &cosignOptions)
			if err != nil {
				fmt.Printf("signature not verified: %s\n", err.Error())
			}
			if err == nil {
				fmt.Printf("signature %d satisfies verifier %s\n", i, verifier.Name)
				satisfiedVerifiers = append(satisfiedVerifiers, verifier.Name)
				break
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
		return errors.New("providing an SCTPublicKey in the root of trust configuration has not yet been implemented")
	} else {
		cosignOptions.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return fmt.Errorf("error retrieving default CT log public keys: %s", err.Error())
		}
	}
	return nil
}

func setVerifierCosignOptions(cosignOptions *cosign.CheckOpts, verifier Verifier, ctx context.Context) (err error) {
	switch verifier.Type {
	case "keypair":
		cosignOptions.SigVerifier, err = sig.LoadPublicKeyRaw([]byte(verifier.KeyPairOptions.PublicKey), crypto.SHA256)
		if err != nil {
			return fmt.Errorf("could not load verifier's pem encoded public key: %s", err.Error())
		}
	case "keyless":
		cosignOptions.Identities = []cosign.Identity{
			{
				Issuer:  verifier.KeylessOptions.CertIssuer,
				Subject: verifier.KeylessOptions.CertSubject,
			},
		}
	default:
		return fmt.Errorf("invalid verification type in config file, must be either \"keypair\" or \"keyless\", got \"%s\"", verifier.Type)
	}
	cosignOptions.IgnoreTlog = verifier.IgnoreTLog
	cosignOptions.IgnoreSCT = verifier.IgnoreSCT
	return nil
}
