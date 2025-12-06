package scanner

import (
    "aws-security-scanner/models"
    "fmt"
    
    "github.com/aws/aws-sdk-go/service/s3"
)

/*
S3 checks - looking for common misconfigurations

Java equivalent:
@Service
public class S3Scanner {
    @Autowired
    private AmazonS3 s3Client;
    
    public List<Finding> scan() {
        List<Bucket> buckets = s3Client.listBuckets();
        // check each bucket...
    }
}
*/

// scanS3 checks S3 buckets for security issues
func (s *Scanner) scanS3() error {
    // Create S3 client (like @Autowired in Spring)
    svc := s3.New(s.session)
    
    // List all buckets
    // Java: ListBucketsResult result = s3Client.listBuckets();
    result, err := svc.ListBuckets(nil)
    if err != nil {
        return fmt.Errorf("failed to list S3 buckets: %w", err)
    }
    
    fmt.Printf("  Found %d S3 buckets\n", len(result.Buckets))
    
    // Check each bucket
    // Java: for (Bucket bucket : result.getBuckets()) { ... }
    for _, bucket := range result.Buckets {
        s.checkBucketEncryption(svc, bucket)
        s.checkBucketPublicAccess(svc, bucket)
        s.checkBucketVersioning(svc, bucket)
    }
    
    return nil
}

/*
checkBucketEncryption verifies bucket has encryption enabled

Java equivalent:
private void checkBucketEncryption(AmazonS3 client, Bucket bucket) {
    try {
        GetBucketEncryptionResult encryption = 
            client.getBucketEncryption(bucket.getName());
        if (encryption == null) {
            // Add finding...
        }
    } catch (Exception e) {
        // Handle error...
    }
}
*/

// checkBucketEncryption checks if bucket has encryption enabled
func (s *Scanner) checkBucketEncryption(svc *s3.S3, bucket *s3.Bucket) {
    // Get bucket name
    // In Go, AWS SDK uses pointers for optional values
    // *bucket.Name dereferences the pointer to get the string value
    bucketName := *bucket.Name
    
    // Check encryption configuration
    input := &s3.GetBucketEncryptionInput{
        Bucket: bucket.Name,
    }
    
    _, err := svc.GetBucketEncryption(input)
    
    // If error getting encryption, bucket is not encrypted
    if err != nil {
        finding := models.NewHighFinding(
            bucketName,
            models.ResourceS3,
            "S3 Bucket Not Encrypted",
            fmt.Sprintf("Bucket '%s' does not have server-side encryption enabled. "+
                "Data at rest is not protected.", bucketName),
        )
        s.addFinding(finding)
    }
}

// checkBucketPublicAccess checks if bucket allows public access
func (s *Scanner) checkBucketPublicAccess(svc *s3.S3, bucket *s3.Bucket) {
    bucketName := *bucket.Name
    
    // Check bucket ACL
    input := &s3.GetBucketAclInput{
        Bucket: bucket.Name,
    }
    
    result, err := svc.GetBucketAcl(input)
    if err != nil {
        // Can't determine - skip
        return
    }
    
    // Check if any grant allows public access
    // Java: for (Grant grant : result.getGrants()) { ... }
    for _, grant := range result.Grants {
        // Check if grantee is public
        if grant.Grantee.URI != nil {
            uri := *grant.Grantee.URI
            
            // AllUsers or AuthenticatedUsers means public
            if uri == "http://acs.amazonaws.com/groups/global/AllUsers" ||
               uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
                
                finding := models.NewCriticalFinding(
                    bucketName,
                    models.ResourceS3,
                    "S3 Bucket Publicly Accessible",
                    fmt.Sprintf("Bucket '%s' allows public access via ACL. "+
                        "This could expose sensitive data to the internet.", bucketName),
                )
                s.addFinding(finding)
                return // Only report once per bucket
            }
        }
    }
}

// checkBucketVersioning checks if versioning is enabled
func (s *Scanner) checkBucketVersioning(svc *s3.S3, bucket *s3.Bucket) {
    bucketName := *bucket.Name
    
    input := &s3.GetBucketVersioningInput{
        Bucket: bucket.Name,
    }
    
    result, err := svc.GetBucketVersioning(input)
    if err != nil {
        return
    }
    
    // Check if versioning is not enabled
    if result.Status == nil || *result.Status != "Enabled" {
        finding := models.NewMediumFinding(
            bucketName,
            models.ResourceS3,
            "S3 Bucket Versioning Disabled",
            fmt.Sprintf("Bucket '%s' does not have versioning enabled. "+
                "Cannot recover from accidental deletion or modification.", bucketName),
        )
        s.addFinding(finding)
    }
}