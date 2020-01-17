package main

import (
    "bytes"
    "crypto/ed25519"
    "encoding/base64"
    "errors"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "sort"
    "strconv"
    "strings"
    "time"
)

type Signature string

func requestToSigString(r *http.Request) (string, error) {
    defer r.Body.Close()
    var (
        singString string
    )
    q := r.URL.Query()
    qkeys := make([]string, len(q))
    i := 0
    for k := range q {
        qkeys[i] = k
        i++
    }
    sort.Strings(qkeys)
    for _, v := range qkeys {
        singString = singString + strings.Join(q[v], "")
    }
    if r.Body != nil {
        originalRBody := r.Body
        defer originalRBody.Close()
        if byteBodyString, err := ioutil.ReadAll(r.Body); err != nil {
            return "", err
        } else {
            r.Body = ioutil.NopCloser(bytes.NewBuffer(byteBodyString))
            singString = singString + string(byteBodyString)
        }
    }
    //Required Headers
    for _, headerName := range []string{"X-REQUEST-TIME"} {
        if headerValue := r.Header.Get(headerName); headerValue == "" {
            return "", errors.New("missing " + headerName)
        } else {
            singString = singString + headerValue
        }
    }
    //Optional Headers
    for _, headerName := range []string{"X-API-USER-AUTH", "X-AUTH-PARTNER-ID"} {
        if headerValue := r.Header.Get(headerName); headerValue != "" {
            singString = singString + headerValue
        }
    }
    return singString, nil
}

func Sign(r *http.Request, pk ed25519.PrivateKey) (Signature, error) {
    if singString, err := requestToSigString(r); err != nil {
        return "", err
    } else {
        signBytes := ed25519.Sign(pk, []byte(singString))
        signature := Signature(base64.StdEncoding.EncodeToString(signBytes))
        return signature, nil
    }
}

func Check(r *http.Request, signature Signature, pubk ed25519.PublicKey) (bool, error) {
    if singString, err := requestToSigString(r); err != nil {
        return false, err
    } else {
        if signatureBytes, err := base64.StdEncoding.DecodeString(string(signature)); err != nil {
            return false, err
        }else{
            ok := ed25519.Verify(pubk, []byte(singString), signatureBytes)
            return ok, nil
        }
    }
    return false, nil
}

func main() {
    var (
        privKey ed25519.PrivateKey
        r       *http.Request
        sig     Signature
        err     error
    )
    if _, privKey, err = ed25519.GenerateKey(nil); err != nil {
        log.Fatal(err)
    }

    privKeyString := base64.StdEncoding.EncodeToString(privKey)

    fmt.Printf("PrivK: %v \n", privKeyString)

    if r, err = http.NewRequest(http.MethodPost, "https://gamebackend.com/api/sync/task/?c=asd1&1=b&a=2", strings.NewReader(`
        {"task_id": "string",
        "task_type": "string",
        "assets": [
    {
        "origin_id":  "string",
        "varaint_id": "string",
        "quantity":   "int",
    }]}`)); err != nil {
        log.Fatal(err)
    }

    r.Header.Add("Content-Type", "application/json")
    r.Header.Add("X-REQUEST-TIME", strconv.Itoa(int(time.Now().Unix())))
    r.Header.Add("X-AUTH-PARTNER-ID", "partner_id")
    r.Header.Add("X-API-VERSION", "v1")

    if sig, err = Sign(r, privKey); err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Signature: %v \n", sig)
    if ok, err := Check(r, sig, privKey.Public().(ed25519.PublicKey)); err != nil {
        log.Fatal(err)
    } else {
        fmt.Printf("Check: %v \n", ok)
    }
}