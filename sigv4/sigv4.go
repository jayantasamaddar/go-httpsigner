package sigv4

import (
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jayantasamaddar/go-httpsigner/auth"
	"github.com/jayantasamaddar/go-httpsigner/utils"
)

// Errors
const (
	ERROR_MANDATORY_FIELD_NOT_SPECIFIED = "Mandatory field not specified"
	ERROR_READ_ENVIRONMENT_VARIABLES    = "Could not read environment variables at `ACCESS_KEY_ID`, `SECRET_ACCESS_KEY` and `REGION`"
	ERROR_NO_CONFIG_FILE_FOUND          = "No configuration file found"
)

type SigV4 struct {
	// Name of the Organization. Used in different places of the `CanonicalRequest`, `stringToSign` etc.
	org string
	// Abbreviation to be used in Headers as `x-abbr-date`. (E.g. x-amz-date)
	abbr string
	// The service for which this SigV4 algorithm is to be used
	service string
	env     *SigV4EnvConfig
	// Boolean flag to indicate, whether or not to add the `x-[abbr]-content-sha256` header or not. Useful when integrity of the payload is super important.
	//
	// For e.g. Amazon S3 AWS requests require it provided by the `x-amz-content-sha256` header.
	//
	// When set to true, it provides a hash of the request payload in the header `x-[abbr]-content-sha256`.
	// If there is no payload, you must provide the hash of an empty string.
	hashPayload bool
	// URL that is called by a Verifier to get the SECRET_ACCESS_KEY
	secretRetrievalURL string
}

// # Configuration to load environment variables.
//
// Either of the the combinations must be specified:
//   - `ACCESS_KEY_ID`, `SECRET_ACCESS_KEY` and `Region`
//   - `GlobalDir` and/or `GlobalProfile`. If `GlobalProfile` is not specified, "default" is assumed as the profile.
//
// The `GlobalDir` is expected to have two files `credentials` and `config`.
//
// If both of the two combinations are specified, the environment variables are looked into first, and then the `GlobalDir` and `GlobalProfile`.
// Doesn't look into `GlobalDir` if `ACCESS_KEY_ID`, `SECRET_ACCESS_KEY` and `Region` are already found as environment variables.
type SigV4EnvConfig struct {
	ACCESS_KEY_ID     string // The ACCESS_KEY_ID. (E.g. for AWS, this is `aws_access_key_id` for the profile)
	SECRET_ACCESS_KEY string // The SECRET_ACCESS_KEY. (E.g. for AWS, this is `aws_secret_access_key` for the profile)
	REGION            string // The region
	// Instead of specifying the credentials directly, specify the Directory path to load environment variables from.
	//
	// E.g. For AWS:
	//
	// - Linux and BSD-based systems: `/Users/USER/.aws`
	//
	// - Windows:  `C:/Users/$USER/.aws`
	//
	// There are usually two files inside this directory: `config` and `credentials` (Follows `.aws` folder structure)
	GlobalDir     string
	GlobalProfile string // The profile to use for `GlobalDir/config` and `GlobalDir/credentials`
}

// Constructor to create Verifier Object
func NewSigV4Verifier(org, abbr, service, secretRetrievalURL string) (auth.Verifier, error) {
	if service == "" {
		return nil, fmt.Errorf("%s: %s", ERROR_MANDATORY_FIELD_NOT_SPECIFIED, "service")
	}
	if secretRetrievalURL == "" {
		return nil, fmt.Errorf("%s: %s", ERROR_MANDATORY_FIELD_NOT_SPECIFIED, "secretRetrievalURL")
	}
	// If no `org` is provided, assume it is "AWS"
	if org == "" {
		org = "AWS"
	}
	// // If no `abbr` is provided, assume it is "amz"
	if abbr == "" {
		abbr = "amz"
	}
	return &SigV4{org: org, abbr: abbr, service: service, hashPayload: false, env: new(SigV4EnvConfig), secretRetrievalURL: secretRetrievalURL}, nil
}

// Constructor to create a Signer Object
func NewSigV4Signer(org, abbr, service string, env *SigV4EnvConfig, hashPayload bool) (auth.Signer, error) {
	if service == "" {
		return nil, fmt.Errorf("%s: %s", ERROR_MANDATORY_FIELD_NOT_SPECIFIED, "service")
	}
	s := SigV4{org, abbr, service, env, hashPayload, ""}
	// If no `org` is provided, assume it is "AWS"
	if org == "" {
		s.org = "AWS"
	}
	// // If no `abbr` is provided, assume it is "amz"
	if abbr == "" {
		s.abbr = "amz"
	}
	// If `SigV4EnvConfig` IS NOT PROVIDED, first attempt to load environment variables automatically.
	// If no environment variables are present, then attempt to read from the `$HOME/.Lowercase(org)`, where HOME is the Home Directory of the current user.
	//
	// E.g. If no org was `AWS`, on a Linux and BSD-based system, the directory to read from after failure to read environment variables would be:
	// 	`/Users/{CurrentUser}/.aws`
	if env == nil {
		id, secret, region := os.Getenv("ACCESS_KEY_ID"), os.Getenv("SECRET_ACCESS_KEY"), os.Getenv("REGION")
		s.env = &SigV4EnvConfig{
			ACCESS_KEY_ID:     id,
			SECRET_ACCESS_KEY: secret,
			REGION:            region,
		}
		// If all environment variables are present, return the signer
		if id != "" && secret != "" && region != "" {
			return &s, nil
		}
		if id != "" || secret != "" || region != "" {
			// By default read `.aws` directory
			homeDir, err := utils.HomeDir()
			if err != nil {
				return nil, fmt.Errorf("%s: %s", ERROR_READ_ENVIRONMENT_VARIABLES, err)
			}
			s.env.GlobalDir = filepath.Join(homeDir, fmt.Sprintf(".%s", strings.ToLower(s.org)))
			s.env.GlobalProfile = "default"
		}
	}

	// If all environment variables are present, return the signer
	if s.env.ACCESS_KEY_ID != "" && s.env.SECRET_ACCESS_KEY != "" && s.env.REGION != "" {
		return &s, nil
	}

	// Else, some environment variables are present, some aren't, which means, we have to read the `GlobalDir` and `GlobalConfig`
	//
	// Check if `GlobalDir` and `GlobalConfig` are present

	// Set default `GlobalDir` if not present
	if s.env.GlobalDir == "" {
		homeDir, err := utils.HomeDir()
		if err != nil {
			return nil, fmt.Errorf("%s: %s", ERROR_READ_ENVIRONMENT_VARIABLES, err)
		}
		s.env.GlobalDir = filepath.Join(homeDir, fmt.Sprintf(".%s", strings.ToLower(s.org)))
	}
	// Set default `GlobalProfile` if not present
	if s.env.GlobalProfile == "" {
		s.env.GlobalProfile = "default"
	}

	// Read from `GlobalDir`
	entries, err := os.ReadDir(s.env.GlobalDir)
	if err != nil {
		return nil, fmt.Errorf("%s: %s & %s",
			ERROR_NO_CONFIG_FILE_FOUND,
			ERROR_READ_ENVIRONMENT_VARIABLES,
			fmt.Sprintf("Could not read from %s", s.env.GlobalDir),
		)
	}
	// Error: Could read directory, but no config files found.
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s | %s", ERROR_READ_ENVIRONMENT_VARIABLES, ERROR_NO_CONFIG_FILE_FOUND)
	}

	// Iterate over files
	for _, file := range entries {
		// Check if the file doesn't have an extension or has an extension of interest
		ext := filepath.Ext(file.Name())
		switch ext {
		case "":
			fallthrough // Proceed to read as .ini file
		case ".ini", ".conf", ".config":
			for profile := range utils.ReadIniFile(filepath.Join(s.env.GlobalDir, file.Name())) {
				if profile.Name != s.env.GlobalProfile {
					continue
				}
				if s.env.ACCESS_KEY_ID != "" && s.env.SECRET_ACCESS_KEY != "" && s.env.REGION != "" {
					break
				}

				// Find `ACCESS_KEY_ID`
				if s.env.ACCESS_KEY_ID == "" {
					if access, ok := profile.Map[fmt.Sprintf("%s_access_key_id", strings.ToLower(s.org))]; ok {
						s.env.ACCESS_KEY_ID = access
					}
				}

				// Find `SECRET_ACCESS_KEY`
				if s.env.SECRET_ACCESS_KEY == "" {
					if access, ok := profile.Map[fmt.Sprintf("%s_secret_access_key", strings.ToLower(s.org))]; ok {
						s.env.SECRET_ACCESS_KEY = access
					}
				}

				// Find `REGION`
				if s.env.REGION == "" {
					if access, ok := profile.Map["region"]; ok {
						s.env.REGION = access
					}
				}
			}
		case ".env":
			profile, err := utils.ReadEnvFile(filepath.Join(s.env.GlobalDir, file.Name()))
			if err != nil {
				log.Println("Error reading from:", filepath.Join(s.env.GlobalDir, file.Name()))
				return &s, err
			}

			if s.env.ACCESS_KEY_ID != "" && s.env.SECRET_ACCESS_KEY != "" && s.env.REGION != "" {
				break
			}

			// Find `ACCESS_KEY_ID`
			if s.env.ACCESS_KEY_ID == "" {
				if access, ok := profile.Map[fmt.Sprintf("%s_access_key_id", strings.ToLower(s.org))]; ok {
					s.env.ACCESS_KEY_ID = access
				}
			}

			// Find `SECRET_ACCESS_KEY`
			if s.env.SECRET_ACCESS_KEY == "" {
				if access, ok := profile.Map[fmt.Sprintf("%s_secret_access_key", strings.ToLower(s.org))]; ok {
					s.env.SECRET_ACCESS_KEY = access
				}
			}

			// Find `REGION`
			if s.env.REGION == "" {
				if access, ok := profile.Map["region"]; ok {
					s.env.REGION = access
				}
			}

		default:
			fmt.Printf("Skipping file %s with unsupported extension\n", file.Name())
		}
	}
	return &s, nil
}

// Generate the Date Header name
func (s *SigV4) dateHeader() string {
	return fmt.Sprintf("X-%s-Date", s.abbr)
}

// (3a) The credential scope. This restricts the resulting signature to the specified Region and service.
// The string has the following format: YYYYMMDD/region/service/aws4_request.
func (s *SigV4) getCredentialScope(dateString, region, service string) string {
	// Parse the date string
	parsedTime, err := time.Parse(time.RFC3339Nano, dateString)
	if err != nil {
		panic(err)
	}
	//Extract year, month, and day
	YYYY, MM, DD := parsedTime.Date()
	return fmt.Sprintf("%s/%s/%s",
		fmt.Sprintf("%d%d%d", YYYY, MM, DD),
		region,
		service,
	)
}

// (4) Calculate the signature. Takes in a `SigningKey` and `stringToSign` and returns the signature.
func (s *SigV4) generateSignature(signingKey []byte, stringToSign string) (string, error) {
	hmac, err := utils.HmacSHA256(signingKey, stringToSign)
	return hex.EncodeToString(hmac), err
}

// (5) Takes in a pointer to a http.Request and add the Signature to the Authorization Header.
// The Signer only needs access to this method to sign a HTTP Request. This method utilizes all other sub-methods, like `CanonicalRequest`.
func (s *SigV4) SignHTTPRequest(req *http.Request) error {
	// Set the time
	req.Header.Set(s.dateHeader(), time.Now().Format(time.RFC3339Nano))

	// (1) Get the `CanonicalRequest`
	cr, err := s.canonicalRequest(req)
	if err != nil {
		return err
	}

	// (2) Generate the `stringToSign`
	s2s := s.stringToSign(req.Header.Get(s.dateHeader()), s.env.REGION, s.service, cr)

	// (3) Generate the `SigningKey`
	sk, err := s.signingKey(s.env.SECRET_ACCESS_KEY, req.Header.Get(s.dateHeader()), s.env.REGION, s.service)
	if err != nil {
		return err
	}

	// (4) Calculate and return signature
	signature, err := s.generateSignature(sk, s2s)
	if err != nil {
		return err
	}

	// Credential: A string that consists of your access key ID, the date in YYYYMMDD format, the Region code, the service code, and the aws4_request termination string, separated by slashes (/). The Region code, service code, and termination string must use lowercase characters.
	// E.g. `AKIAIOSFODNN7EXAMPLE/YYYYMMDD/region/service/aws4_request`
	authHeader := fmt.Sprintf("%s %s,%s,%s",
		"AWS4-HMAC-SHA256",
		fmt.Sprintf("Credential=%s/%s", s.env.ACCESS_KEY_ID, s.getCredentialScope(req.Header.Get(s.dateHeader()), s.env.REGION, s.service)),
		fmt.Sprintf("SignedHeaders=%s", "content-type;host;x-sym-date"),
		fmt.Sprintf("Signature=%s", signature),
	)
	req.Header.Set("Authorization", authHeader)
	return nil
}
