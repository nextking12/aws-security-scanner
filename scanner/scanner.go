package scanner

import (
    "aws-security-scanner/models"
    "fmt"
    "sync"
    
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/session"
)

/*
Scanner is the main orchestrator - like a @Service in Spring Boot

In Java:
@Service
public class SecurityScanner {
    @Autowired
    private S3Client s3Client;
    @Autowired
    private EC2Client ec2Client;
    
    public List<Finding> scan() { ... }
}

In Go, we use a struct to hold dependencies (like fields in a Java class)
*/

// Scanner coordinates all security checks
type Scanner struct {
    session  *session.Session  // AWS session (like @Autowired AWS client)
    region   string
    findings []*models.Finding // Slice of Finding pointers (like List<Finding>)
    mu       sync.Mutex        // Mutex for thread-safe access (like synchronized in Java)
}

/*
Constructor function - this is the Go idiom for "new"

Java equivalent:
@Autowired
public SecurityScanner(AWSCredentialsProvider credentials) {
    this.session = new Session(credentials);
}
*/

// NewScanner creates a new Scanner instance
func NewScanner(region string) (*Scanner, error) {
    // Create AWS session (like Spring's AWS client auto-configuration)
    sess, err := session.NewSession(&aws.Config{
        Region: aws.String(region),
    })
    
    // Go's error handling: functions return (result, error)
    // Always check err != nil (like catching exceptions in Java)
    if err != nil {
        return nil, fmt.Errorf("failed to create AWS session: %w", err)
    }
    
    // Return pointer to new Scanner
    // & means "address of" - creates a pointer
    return &Scanner{
        session:  sess,
        region:   region,
        findings: make([]*models.Finding, 0), // Create empty slice (like new ArrayList<>())
    }, nil
}

/*
Scan runs all security checks

Java equivalent:
public List<Finding> scan() {
    List<Finding> findings = new ArrayList<>();
    findings.addAll(scanS3());
    findings.addAll(scanEC2());
    findings.addAll(scanIAM());
    return findings;
}
*/

// Scan executes all security checks
func (s *Scanner) Scan() error {
    fmt.Println("🔍 Starting AWS security scan...")
    fmt.Printf("Region: %s\n\n", s.region)
    
    // Run S3 checks
    fmt.Println("Scanning S3 buckets...")
    if err := s.scanS3(); err != nil {
        return fmt.Errorf("S3 scan failed: %w", err)
    }
    
    // Run EC2/Security Group checks
    fmt.Println("Scanning Security Groups...")
    if err := s.scanSecurityGroups(); err != nil {
        return fmt.Errorf("Security Group scan failed: %w", err)
    }
    
    // Run IAM checks
    fmt.Println("Scanning IAM users...")
    if err := s.scanIAM(); err != nil {
        return fmt.Errorf("IAM scan failed: %w", err)
    }
    
    fmt.Printf("\n✅ Scan complete. Found %d issues.\n", len(s.findings))
    return nil
}

/*
ScanConcurrent runs checks in parallel using goroutines

This is Go's superpower! Goroutines are like lightweight threads.

Java equivalent (using ExecutorService):
ExecutorService executor = Executors.newFixedThreadPool(3);
List<Future<List<Finding>>> futures = new ArrayList<>();
futures.add(executor.submit(() -> scanS3()));
futures.add(executor.submit(() -> scanEC2()));
futures.add(executor.submit(() -> scanIAM()));
// Wait for all and collect results...

Go makes this MUCH simpler with goroutines and channels!
*/

// ScanConcurrent runs all checks in parallel (demonstrates goroutines)
func (s *Scanner) ScanConcurrent() error {
    fmt.Println("🔍 Starting concurrent AWS security scan...")
    fmt.Printf("Region: %s\n\n", s.region)
    
    // WaitGroup is like CountDownLatch in Java
    // Waits for all goroutines to complete
    var wg sync.WaitGroup
    
    // Channel to collect errors (like a queue)
    // Channels are Go's way of communicating between goroutines
    errChan := make(chan error, 3) // Buffer of 3 (one per check)
    
    // Launch S3 scan in goroutine (like executor.submit())
    wg.Add(1) // Increment counter
    go func() {
        defer wg.Done() // Decrement when done (like finally block)
        fmt.Println("Scanning S3 buckets...")
        if err := s.scanS3(); err != nil {
            errChan <- err // Send error to channel
        }
    }()
    
    // Launch Security Group scan
    wg.Add(1)
    go func() {
        defer wg.Done()
        fmt.Println("Scanning Security Groups...")
        if err := s.scanSecurityGroups(); err != nil {
            errChan <- err
        }
    }()
    
    // Launch IAM scan
    wg.Add(1)
    go func() {
        defer wg.Done()
        fmt.Println("Scanning IAM users...")
        if err := s.scanIAM(); err != nil {
            errChan <- err
        }
    }()
    
    // Wait for all goroutines to complete
    wg.Wait()
    close(errChan) // Close channel when done
    
    // Check if any errors occurred
    for err := range errChan {
        if err != nil {
            return err
        }
    }
    
    fmt.Printf("\n✅ Concurrent scan complete. Found %d issues.\n", len(s.findings))
    return nil
}

/*
GetFindings returns all findings

Java equivalent:
public List<Finding> getFindings() {
    return new ArrayList<>(findings); // Return copy
}

In Go, slices are reference types (like arrays in Java), so we return directly
*/

// GetFindings returns all discovered security findings
func (s *Scanner) GetFindings() []*models.Finding {
    return s.findings
}

/*
addFinding adds a finding to the list (thread-safe)

Java equivalent:
private synchronized void addFinding(Finding f) {
    findings.add(f);
}

In Go, we use mutex for synchronization
*/

// addFinding adds a finding to the internal list (thread-safe)
func (s *Scanner) addFinding(finding *models.Finding) {
    // Lock mutex (like synchronized block)
    s.mu.Lock()
    defer s.mu.Unlock() // Unlock when function returns (like finally)
    
    finding.Region = s.region
    s.findings = append(s.findings, finding) // append is like ArrayList.add()
}

/*
GetFindingsBySeverity filters findings

Java equivalent (using Stream API):
public List<Finding> getFindingsBySeverity(String severity) {
    return findings.stream()
        .filter(f -> f.getSeverity().equals(severity))
        .collect(Collectors.toList());
}
*/

// GetFindingsBySeverity returns findings matching a specific severity
func (s *Scanner) GetFindingsBySeverity(severity string) []*models.Finding {
    // Create new slice for filtered results
    filtered := make([]*models.Finding, 0)
    
    // Iterate through findings (like for-each in Java)
    for _, finding := range s.findings {
        if finding.Severity == severity {
            filtered = append(filtered, finding)
        }
    }
    
    return filtered
}

// GetCriticalFindings returns only critical findings
func (s *Scanner) GetCriticalFindings() []*models.Finding {
    return s.GetFindingsBySeverity(models.SeverityCritical)
}