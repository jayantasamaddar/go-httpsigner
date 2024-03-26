package sigv4

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jayantasamaddar/go-httpsigner/utils"
)

/*************************************************************************************************************/
// Signer Tests
/*************************************************************************************************************/

// Test Signer with `service` not provided
func Test_SigV4SignerWithNoService(t *testing.T) {
	_, err := NewSigV4Signer("", "", "", nil, false)
	if err == nil {
		t.Error(err)
	} else {
		t.Log("Correctly throws an error:", err)
	}
}

// Test Signer with default settings
func Test_DefaultSigV4Signer(t *testing.T) {
	signer, err := NewSigV4Signer("", "", "s3", nil, false)
	if err != nil {
		t.Error(err)
	}

	if s, ok := signer.(*SigV4); !ok {
		t.Errorf("Signer not of type: %T", SigV4{})
	} else {
		globalDir, err := utils.HomeDir()
		if err != nil {
			t.Fatal(err)
		}
		if s.env.GlobalDir != filepath.Join(globalDir, ".aws") {
			t.Error("GlobalDir mismatch")
		}
		if s.env.GlobalProfile != "default" {
			t.Error("GlobalProfile mismatch")
		}
	}
}

// Test Signer with all required environment variables
func Test_SigV4Signer_With_NilEnvConfig_And_All_EnvironmentVariables(t *testing.T) {
	// Environment variables present
	os.Setenv("ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	os.Setenv("SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	os.Setenv("REGION", "ap-south-1")

	signer, err := NewSigV4Signer("ZEN", "zns", "messagequeue", nil, false)
	if err != nil {
		t.Fatal(err)
	}

	if s, ok := signer.(*SigV4); !ok {
		t.Errorf("Signer not of type: %T", SigV4{})
	} else {
		if s.env.ACCESS_KEY_ID == "" || s.env.SECRET_ACCESS_KEY == "" || s.env.REGION == "" {
			t.Errorf("Failed to read environment variables")
		} else {
			t.Log("Correctly read and stored environment variables")
		}
	}
}

// Test Signer with some of the required environment variables
func Test_SigV4Signer_With_NilEnvConfig_And_Some_EnvironmentVariables(t *testing.T) {
	// Environment variables present
	os.Setenv("ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	os.Setenv("SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	os.Unsetenv("REGION")
	// REGION not provided

	signer, err := NewSigV4Signer("", "", "s3", nil, false)
	if err != nil {
		t.Fatal(err)
	}

	if s, ok := signer.(*SigV4); !ok {
		t.Errorf("Signer not of type: %T", SigV4{})
	} else {
		if s.env.GlobalDir == "" || s.env.GlobalProfile == "" {
			t.Errorf("Expected GlobalDir and GlobalProfile to be set to defaults")
		} else {
			t.Log("Correctly set GlobalDir and GlobalProfile")
		}
	}
}

/*************************************************************************************************************/
// Verifier Tests
/*************************************************************************************************************/

// Test Verifier with `service` not provided
func Test_SigV4VerifierWithNoService(t *testing.T) {
	_, err := NewSigV4Verifier("", "", "", "http://validate.127.0.0.1.sslip.io/api/secret")
	if err == nil {
		t.Error(err)
	} else {
		t.Log("Correctly throws an error:", err)
	}
}

// Test Verifier with `secretRetrievalURL` not provided
func Test_SigV4VerifierWithNoRetrievalURL(t *testing.T) {
	_, err := NewSigV4Verifier("", "", "s3", "")
	if err == nil {
		t.Error(err)
	} else {
		t.Log("Correctly throws an error:", err)
	}
}

// Test Verifier with default settings
func Test_DefaultSigV4Verifier(t *testing.T) {
	verifier, err := NewSigV4Verifier("", "", "s3", "http://validate.127.0.0.1.sslip.io/api/secret")
	if err != nil {
		t.Error(err)
	} else {
		t.Log("SigV4Verifier created successfully")
	}

	if v, ok := verifier.(*SigV4); !ok {
		t.Errorf("Verifier not of type: %T", SigV4{})
	} else {
		if v.org != "AWS" {
			t.Error("org incorrectly set; expected:", "AWS")
		}
		if v.abbr != "amz" {
			t.Error("abbr incorrectly set; expected:", "amz")
		}
	}
}
