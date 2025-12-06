package models

import "time"

/*
In Java, you'd create a POJO with getters/setters:

public class Finding {
    private String resourceId;
    private String resourceType;
    private String severity;
    private String description;
    
    // Getters and setters...
}

In Go, we just use a struct. No getters/setters needed!
Fields starting with uppercase are public (exported).
Fields starting with lowercase are private.
*/

// Finding represents a security issue found in AWS
type Finding struct {
    ResourceID   string    `json:"resource_id"`   // `json:...` is like @JsonProperty in Jackson
    ResourceType string    `json:"resource_type"`
    Severity     string    `json:"severity"`
    Title        string    `json:"title"`
    Description  string    `json:"description"`
    Region       string    `json:"region"`
    Account      string    `json:"account"`
    Timestamp    time.Time `json:"timestamp"`
}

// Severity levels as constants
// In Java: public static final String SEVERITY_CRITICAL = "CRITICAL";
const (
    SeverityCritical = "CRITICAL"
    SeverityHigh     = "HIGH"
    SeverityMedium   = "MEDIUM"
    SeverityLow      = "LOW"
)

// Resource types as constants
const (
    ResourceS3           = "S3_BUCKET"
    ResourceSecurityGroup = "SECURITY_GROUP"
    ResourceEBS          = "EBS_VOLUME"
    ResourceIAM          = "IAM_USER"
)

/*
Go doesn't have constructors, but we use "constructor functions"
This is like a static factory method in Java:

public static Finding newFinding(String resourceId, String type, ...) {
    Finding f = new Finding();
    f.setResourceId(resourceId);
    // ...
    return f;
}
*/

// NewFinding creates a new Finding with default values
func NewFinding(resourceID, resourceType, severity, title, description string) *Finding {
    // & creates a pointer (like "new" in Java)
    // * means pointer type
    return &Finding{
        ResourceID:   resourceID,
        ResourceType: resourceType,
        Severity:     severity,
        Title:        title,
        Description:  description,
        Timestamp:    time.Now(),
    }
}

// Convenience methods for creating findings of different severities
// These are like static factory methods in Java

func NewCriticalFinding(resourceID, resourceType, title, description string) *Finding {
    return NewFinding(resourceID, resourceType, SeverityCritical, title, description)
}

func NewHighFinding(resourceID, resourceType, title, description string) *Finding {
    return NewFinding(resourceID, resourceType, SeverityHigh, title, description)
}

func NewMediumFinding(resourceID, resourceType, title, description string) *Finding {
    return NewFinding(resourceID, resourceType, SeverityMedium, title, description)
}