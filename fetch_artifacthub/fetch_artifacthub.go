// Package main implements an Artifacthub package fetcher with proxy rotation and rate limiting.
//
// The fetcher downloads package data from Artifacthub.io using concurrent requests
// and implements proxy rotation to handle rate limiting. It includes features for
// error handling, retries, and data persistence.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
	"github.com/gocolly/colly/v2/proxy"
	"github.com/schollz/progressbar/v3"
	"gopkg.in/yaml.v2"
)

// Config holds the application configuration loaded from YAML
type Config struct {
	Concurrency     int           `yaml:"concurrency"`  // Number of concurrent requests
	ProxyListURL    string        `yaml:"proxy_list_url"` // URL to fetch proxy list
	RateLimit       int           `yaml:"rate_limit"`   // API rate limit per minute
	MaxRetries      int           `yaml:"max_retries"`  // Maximum retry attempts
	Timeout         time.Duration `yaml:"timeout"`      // Request timeout duration
	DataDir         string        `yaml:"data_dir"`     // Directory to store data
	LogFile         string        `yaml:"log_file"`     // Log file path
	Limit           int           `yaml:"limit"`        // Limit of packages to fetch
	RetryWaitPeriod time.Duration `yaml:"retry_wait_period"`
	ProxyTimeout    time.Duration `yaml:"proxy_timeout"`
	UseProxies      bool          `yaml:"use_proxies"`
}

// ProxyManager handles proxy rotation and validation
type ProxyManager struct {
	proxies []string      // List of available proxies
	mu      sync.RWMutex  // Mutex for thread-safe proxy access
}

// PackageFetcher handles the fetching of package data from Artifacthub
type PackageFetcher struct {
	proxyManager *ProxyManager  // Proxy rotation manager
	config       *Config        // Application configuration
}

// SearchResponse represents the API response structure
type SearchResponse struct {
	Packages []json.RawMessage `json:"packages"`  // Raw package data
}

// Error definitions for common failure scenarios
var (
	ErrTooManyRequests = fmt.Errorf("too many requests")
	ErrServerError     = fmt.Errorf("server error")
	ErrNoMorePackages  = fmt.Errorf("no more packages to fetch")
)

// main initializes and runs the package fetcher
func main() {
	// Load configuration from YAML file
	config, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Set up logging output
	setupLogging(config.LogFile)

	// Create a new package fetcher instance
	fetcher := NewPackageFetcher(config)

	// Run the package fetcher
	fetcher.Run()
}

// loadConfig loads and parses the YAML configuration file
func loadConfig(filename string) (*Config, error) {
	// Read the configuration file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	// Unmarshal the YAML data into the Config struct
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	return &config, nil
}

// setupLogging configures the logging output
func setupLogging(logFile string) {
	// Open the log file in append mode
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	mw := io.MultiWriter(os.Stdout, file)
	log.SetOutput(mw) // Set the log output to the file
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

// NewPackageFetcher creates a new instance of PackageFetcher
func NewPackageFetcher(config *Config) *PackageFetcher {
	pm := &ProxyManager{}
	return &PackageFetcher{
		proxyManager: pm,
		config:       config,
	}
}

// UpdateProxies updates the list of available proxies from the configured URL
// It validates each proxy before adding it to the available proxies list
func (pm *ProxyManager) UpdateProxies(config *Config) error {
	// Lock the mutex to ensure thread-safe access
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Fetch the proxy list
	resp, err := http.Get(config.ProxyListURL)
	if err != nil {
		return fmt.Errorf("fetching proxy list: %w", err)
	}
	defer resp.Body.Close()

	// Create a buffered channel to store proxies
	proxyChan := make(chan string, 1000)

	// Start a goroutine to read proxies
	go func() {
		defer close(proxyChan)
	scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024) // Increase buffer size
	for scanner.Scan() {
			proxyChan <- scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error scanning proxies: %v", err)
		}
	}()

	// Count proxies for progress bar
	var proxyCount int64
	countChan := make(chan struct{})
	go func() {
		for range proxyChan {
			proxyCount++
		}
		close(countChan)
	}()

	// Create a progress bar
	bar := progressbar.Default(-1, "Validating proxies")

	var proxies []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, 100) // Increase concurrent goroutines

	for proxy := range proxyChan {
		wg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore
		go func(p string) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release semaphore
			if pm.isProxyValid(p, config.ProxyTimeout) {
				mu.Lock()
				proxies = append(proxies, p)
				mu.Unlock()
			}
			bar.Add(1)
		}(proxy)
		}

	wg.Wait()
	<-countChan // Wait for proxy counting to finish
	fmt.Println() // Add a newline after the progress bar

	pm.proxies = proxies
	log.Printf("Fetched and validated %d proxies out of %d", len(pm.proxies), proxyCount)
	return nil
}

// isProxyValid checks if a proxy is working by making a test request
func (pm *ProxyManager) isProxyValid(proxyURL string, timeout time.Duration) bool {
	proxyURLParsed, err := url.Parse("http://" + proxyURL)
	if err != nil {
		return false
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURLParsed),
		},
		Timeout: timeout,
	}

	resp, err := client.Head("https://artifacthub.io")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// GetProxy returns a random proxy from the available proxies list
func (pm *ProxyManager) GetProxy() string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if len(pm.proxies) == 0 {
		return ""
	}
	return pm.proxies[rand.Intn(len(pm.proxies))]
}

// Run executes the main package fetching logic
// It handles proxy rotation, rate limiting, and data persistence
func (pf *PackageFetcher) Run() {
	log.Println("Starting package fetcher...")

	if pf.config.UseProxies {
		if err := pf.proxyManager.UpdateProxies(pf.config); err != nil {
			log.Printf("Error updating proxies: %v", err)
		}
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, pf.config.Concurrency)
	done := make(chan bool)

	for offset := 0; ; offset += pf.config.Limit {
		wg.Add(1)
		sem <- struct{}{}
		go func(offset int) {
			defer wg.Done()
			defer func() { <-sem }()
			success, err := pf.fetchPackagesWithRetry(offset, pf.config.Limit)
		if err != nil {
			if err == ErrNoMorePackages {
					log.Printf("No more packages to fetch at offset %d", offset)
					done <- true
					return
			}
				log.Printf("Error fetching packages at offset %d: %v", offset, err)
			}
			if !success {
				log.Printf("Failed to fetch packages at offset %d", offset)
				done <- true
				return
			}
		}(offset)

		select {
		case <-done:
			close(sem)
			wg.Wait()
			log.Println("Finished fetching all packages")
			return
		default:
			// Continue fetching
		}
	}
}

func (pf *PackageFetcher) fetchPackagesWithRetry(offset, limit int) (bool, error) {
	for retries := 0; retries < pf.config.MaxRetries; retries++ {
		var proxyURL string
		if pf.config.UseProxies {
			proxyURL = pf.proxyManager.GetProxy()
			if proxyURL != "" {
				log.Printf("Using proxy: %s", proxyURL)
			} else {
				log.Printf("No proxy available, using direct connection")
			}
		}

		success, packages, err := pf.fetchPackages(offset, limit, proxyURL)
		if err == nil {
			if len(packages) < limit {
				return true, ErrNoMorePackages
			}
			return success, nil
		}

		log.Printf("Attempt %d failed: %v", retries+1, err)

		var waitTime time.Duration
		switch {
		case err == ErrTooManyRequests:
			waitTime = pf.config.RetryWaitPeriod * time.Duration(retries+1)
			log.Printf("Rate limited. Retrying in %v...", waitTime)
		case err == ErrServerError:
			waitTime = pf.config.RetryWaitPeriod * time.Duration(retries+1)
			log.Printf("Server error. Retrying in %v...", waitTime)
		default:
			// This includes timeout errors and other network errors
			waitTime = pf.config.RetryWaitPeriod * time.Duration(retries+1)
			log.Printf("Request failed. Retrying in %v...", waitTime)
			}

		time.Sleep(waitTime)
	}

	return false, fmt.Errorf("failed to fetch packages after %d retries", pf.config.MaxRetries)
}

// fetchPackages fetches a batch of packages from Artifacthub
func (pf *PackageFetcher) fetchPackages(offset, limit int, proxyURL string) (bool, []json.RawMessage, error) {
	url := fmt.Sprintf("https://artifacthub.io/api/v1/packages/search?offset=%d&limit=%d&facets=true&kind=0&deprecated=false&sort=relevance", offset, limit)

	var responseErr error
	var responseBody []byte
	success := false

	c := colly.NewCollector(
		colly.Async(true),
		colly.MaxDepth(1),
	)
	c.SetRequestTimeout(pf.config.Timeout)
	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: pf.config.Concurrency,
		RandomDelay: 1 * time.Second,
	})

	if proxyURL != "" {
		rp, err := proxy.RoundRobinProxySwitcher("http://" + proxyURL)
		if err != nil {
			log.Printf("Error setting proxy: %v", err)
		} else {
		c.SetProxyFunc(rp)
	}
	}

	c.OnRequest(func(r *colly.Request) {
		r.Headers.Set("accept", "application/json")
	})

	c.OnResponse(func(r *colly.Response) {
		log.Printf("Received response: Status: %d, Body length: %d", r.StatusCode, len(r.Body))
		
		switch r.StatusCode {
		case http.StatusOK:
			responseBody = r.Body
			success = true
		case http.StatusTooManyRequests:
			responseErr = ErrTooManyRequests
			log.Printf("Rate limited: %s", r.Body)
		case http.StatusInternalServerError:
			responseErr = ErrServerError
			log.Printf("Server error: %s", r.Body)
		default:
			responseErr = fmt.Errorf("unexpected status code: %d", r.StatusCode)
			log.Printf("Unexpected status: %d, Body: %s", r.StatusCode, r.Body)
		}
	})

	c.OnError(func(r *colly.Response, err error) {
		log.Printf("Request error: %v", err)
		responseErr = err
	})

	err := c.Visit(url)
	if err != nil {
		log.Printf("Error visiting URL: %v", err)
		return false, nil, err
	}

	c.Wait()

	if responseErr != nil {
		return false, nil, responseErr
	}

	if success {
		var searchResponse SearchResponse
		err := json.Unmarshal(responseBody, &searchResponse)
		if err != nil {
			log.Printf("Error unmarshaling JSON: %v", err)
			return false, nil, err
		}

		if err := pf.saveRawJSON(responseBody, offset); err != nil {
			log.Printf("Error saving raw JSON: %v", err)
		}

		return true, searchResponse.Packages, nil
	}

	return false, nil, fmt.Errorf("failed to fetch packages")
}

// saveRawJSON saves the raw JSON response to a file in the configured data directory
func (pf *PackageFetcher) saveRawJSON(data []byte, offset int) error {
	if err := os.MkdirAll(pf.config.DataDir, 0755); err != nil {
		return fmt.Errorf("error creating data directory: %v", err)
	}

	filename := filepath.Join(pf.config.DataDir, fmt.Sprintf("packages_raw_%d.json", offset))

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(json.RawMessage(data)); err != nil {
		return fmt.Errorf("error writing JSON: %v", err)
	}

	log.Printf("Saved raw JSON to %s", filename)
	return nil
}