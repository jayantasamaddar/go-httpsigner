# Table of Contents

- [Table of Contents](#table-of-contents)
- [go-httpsigner](#go-httpsigner)
- [Usage](#usage)
  - [Example: SigV4](#example-sigv4)
    - [Example Usage: Client Side](#example-usage-client-side)
  - [Usage: Server Side](#usage-server-side)
- [Currently Implemented Signers](#currently-implemented-signers)
- [Contribution Guidelines](#contribution-guidelines)
- [Reference](#reference)

---

# go-httpsigner

**`go-httpsigner`** is a library to help you implement Signing algorithms to sign HTTP requests, customizable to suit your organization.
It also enable you to behave like a cloud provider who would verify the signed requests.

A good example of this is the [Amazon SigV4 Algorithm](https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html) which is used to sign API requests.
It adds a signature to the request, either as a header or query params that is used by the server to verify the authenticity of the client that sent the request.

While your journey usually ends there, and Amazon takes care of the verification, what if you were to roll your own cloud services and you need a way to sign http requests and verify the signed requests?

Enter `go-httpsigner`.

---

# Usage

The Usage will vary depending on the algorithm. However to make things simple, all algorithms will follow some basic concepts. There is a **Signer** and a **Verifier** (found as interfaces).

- **Signer**: Implemented on the client side that signs the request.
- **Verifier**: Implemented on the server side that verifies the signed request. If you are sending to a Cloud provider like Amazon, you don't have to implement this as Amazon is doing this for you. The Verifier is to be implemented if you are rolling your own service and that's where this library comes handy.

The Interfaces can be viewed at `auth/auth.go`

```go
// Signer interface to be implemented by any signing mechanism.
type Signer interface {
	SignHTTPRequest(req *http.Request) error
}

// Verifier interface to be implemented by any verification mechanism.
type Verifier interface {
	VerifySignature(req *http.Request) error
}
```

The base struct may require varying parameters that can be passed into their respective constructors.
This will vary from algorithm to algorithma and whether it is a signer or a verifier.

> **Note**: For the Verifier, sometimes, additional implementation is necessary.
>
> E.g. In the case of the SigV4, an endpoint able to process a POST request with an `access_key_id` and respond with a `secret_access_key` is necessary for a complete implementation.

---

## Example: SigV4

The SigV4 has two constructors:

1. **`NewSigV4Signer`**: Creates a **`Signer`**.

   - Takes in `org`, `abbr`, `service`, `env` and `hashPayload`.
   - Mandatory fields: `service`

2. **`NewSigV4Verifier`**: Creates a **`Verifier`**.

   - Takes in `org`, `abbr`, `service` and `secretRetrievalURL`.
   - Mandatory fields: `service`, `secretRetrievalURL`

A server endpoint able to handle a POST request to a `secretRetrievalURL` passed to the

### Example Usage: Client Side

```go
package main

import (
    "github.com/jayantasamaddar/go-httpsigner/sigv4"
    "github.com/jayantasamaddar/go-httpsigner/auth"
)

const (
    IMPORTANT_DATA_URL = "http://some-url.com/api/important"
)

// The main app struct that you may use elsewhere in the application
type App struct {
	Name, Version string
	Signer        auth.Signer
}

func main () {
    // You can either set the `ACCESS_KEY_ID`, `SECRET_ACCESS_KEY`, `REGION` or provide `GlobalDir` and `GlobalProfile`.
    // If environment variables and GlobalDir not provided, defaults GlobalDir to $HOMEDIR/.Lower(org). In that case if GlobalProfile not provided,
    // defaults to "default".
    signer, err := sigv4.NewSigV4Signer("ABC", "abc", "myapplication", &sigv4.SigV4EnvConfig{
		ACCESS_KEY_ID:     os.Getenv("ACCESS_KEY_ID"),     // If `nil` *SigV4EnvConfig provided, it will try to read "ACCESS_KEY_ID"
		SECRET_ACCESS_KEY: os.Getenv("SECRET_ACCESS_KEY"), // If `nil` *SigV4EnvConfig provided, it will try to read "SECRET_ACCESS_KEY"
		REGION:            os.Getenv("REGION"),            // If `nil` *SigV4EnvConfig provided, it will try to read "REGION"
	}, false)

    if err != nil {
        // handle error
    }

    app := &App{
        Name: "My Application",
        Version: "v0.1.0",
        Signer: signer
    }

    // Usage
    func (app *app) SendSomeDataToServer(data []byte) {
        // Create a new HTTP request with the POST method and the defined URL
        // request, err := http.NewRequest("POST", url, )
        req, err := http.NewRequest("POST", IMPORTANT_DATA_URL, bytes.NewBuffer([]byte(data)))
        if err != nil {
            app.ErrorLog.Println("Error creating request:", err)
            return
        }

        // Add any headers you want to add here.
        req.Header.Set("Content-Type", "application/json")

        // Sign Request using the SignHTTPRequest.
        // Do not add any headers after this.
        err = app.signer.SignHTTPRequest(req)
        if err != nil {
            panic(err)
        }

        // Send the request using the client
        response, err := app.client.Do(req)
        if err != nil {
            app.ErrorLog.Println("Error sending request:", err)
            return
        }
        defer response.Body.Close()

        // Print the response status code and body
        app.InfoLog.Println("Response Status:", response.Status)
    }
}
```

---

## Usage: Server Side

```go
package main

import (
    "github.com/labstack/echo/v4"
    "github.com/jayantasamaddar/go-httpsigner/sigv4"
    "github.com/jayantasamaddar/go-httpsigner/auth"
)

const (
    SECRET_RETRIEVAL_URL = "http://some-url.com/api/secret"
)

// The main app struct that you may use elsewhere in the application
type App struct {
	Name, Version string
	Signer        auth.Signer
}

func (app *App) StartHTTPServer() {
    e := echo.New()

    // Routes
    api := e.Group("/api")
    api.POST("/important", func(c echo.Context) error {
        // Verify Signature
        err := app.VerifySignature(c.Request())
        if !err {
            return c.String(http.StatusForbidden, "Unauthenticated request")
        }
        // Read Body
        b, _ := io.ReadAll(c.Request().Body)

        return c.String(http.StatusOK, string(b))
    })

    // Start server
    go func() {
        e.Logger.Fatal(e.Start(":1323"))
    }()
}

func main () {
    // The `secretRetrievalURL` is used
    verifier, err := sigv4.NewSigV4Verifier("ABC", "abc", "myapplication", SECRET_RETRIEVAL_URL)
    if err != nil {
        // handle error
    }
    app := &App{
        Name: "My Application",
        Version: "v0.1.0",
        Verifier: verifier
    }

    // Usage

    // Implement code to start and exit server gracefully.
}
```

---

# Currently Implemented Signers

- [Amazon SigV4](./sigv4/)

---

# Contribution Guidelines

- [ ] Getting Coverage Up to 90%: Currently at 72.2%

---

# Reference

- [Publish GoModule](https://go.dev/doc/modules/publishing)
