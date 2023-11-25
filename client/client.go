package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	"github.com/tssig/tssig-go/tssig"
	"net/http"
	"os"
	"time"
)

// MaxHttpDownloadSize Maximum size, in bytes, we'll accept.
const MaxHttpDownloadSize = 768

//---

// Retryable - Error type denoting that we can automatically re-try a request.
type Retryable string

func (e Retryable) Error() string {
	return string(e)
}

//---

// The request format
type payload struct {
	Digest string `json:"digest"`
}

//---

type Client struct {
	// The TSSig server's URL.
	Endpoint string

	// TotalTimeout denotes the total time that we'll keep retrying to get a successful response, including retries.
	TotalTimeout time.Duration

	// Optional function that's updated when a retry occurs.
	Notify backoff.Notify

	HttpClient *http.Client
}

// NewClient Creates a new Client with sensible defaults.
func NewClient(endpoint string) *Client {
	// A TotalTimeout of 60 seconds gives us about 10 attempts, with an Exponential BackOff
	return &Client{
		Endpoint:     endpoint,
		TotalTimeout: 60 * time.Second,
		HttpClient:   &http.Client{Timeout: 5 * time.Second},
	}
}

//---

// Sign Initiates the request to sign the digest, with Exponential BackOff retries in place.
func (c *Client) Sign(digest []byte) (*tssig.SignedTimeStamp, error) {

	switch length := len(digest); length {
	case 224 / 8:
	case 256 / 8:
	case 384 / 8:
	case 512 / 8:
	default:
		return nil, fmt.Errorf(
			"digest must be exactly 224, 256, 384, or 512 bits. %d bits found",
			len(digest)*8,
		)
	}

	// ---

	exponentialBackOff := backoff.NewExponentialBackOff()
	exponentialBackOff.MaxElapsedTime = c.TotalTimeout

	var retryable Retryable

	return backoff.RetryNotifyWithData(
		func() (*tssig.SignedTimeStamp, error) {
			sts, err := c.sign(digest)

			// Check if the error is Retryable, or a timeout...
			if errors.As(err, &retryable) || os.IsTimeout(err) {
				return sts, err
			}

			// If the error is not Retryable, or a timeout, assume it's Permanent.
			return sts, backoff.Permanent(err)
		},
		exponentialBackOff,
		c.Notify,
	)
}

// sign Perform the actual HTTP request to retrieve a Signed Time Stamp.
func (c *Client) sign(digest []byte) (*tssig.SignedTimeStamp, error) {
	requestPayload := &payload{
		Digest: base64.URLEncoding.EncodeToString(digest),
	}

	jsonPayload, err := json.Marshal(requestPayload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.Endpoint, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tssig-client-go")

	response, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode == 429 || response.StatusCode >= 500 {
		return nil, Retryable(fmt.Sprintf("returned non-200 status code %d. we can retry", response.StatusCode))
	} else if response.StatusCode != 200 {
		return nil, fmt.Errorf("returned non-200 status code %d", response.StatusCode)
	}

	if response.ContentLength > MaxHttpDownloadSize {
		return nil, fmt.Errorf(
			"the maximum allowed response size is %d bytes. the returned response is %d bytes",
			MaxHttpDownloadSize,
			response.ContentLength,
		)
	}

	// We add 1 to detect responses' that are too large.
	result := make([]byte, MaxHttpDownloadSize+1)
	n, err := response.Body.Read(result)
	if err != nil {
		return nil, err
	}

	if n > MaxHttpDownloadSize {
		return nil, fmt.Errorf(
			"the maximum allowed response size is %d bytes. the returned response is bigger",
			MaxHttpDownloadSize,
		)
	}

	sts := &tssig.SignedTimeStamp{}
	err = json.Unmarshal(result[:n], sts)
	if err != nil {
		return nil, err
	}

	return sts, nil
}
