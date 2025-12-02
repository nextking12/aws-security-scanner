package models
import "time"

type Finding struct {
	ResourceID string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	Severity string `json:"severity"`
	Title string `json:"title"`
	Description string `json:"description"`
	Region string `json:"region"`
	Account string `json:"account"`
	Timestamp time.Time `json:"timestamp"`
}

const (
	SEVERITY_CRITICAL = "Critical"
	SEVERITY_HIGH = "High"
	SEVERITY_MEDIUM = "Medium"
	SEVERITY_LOW = "Low"
)

const(
	ResourceS3 = "S3_BUCKET"
	ResourceSecurityGroup = "SECURITY_GROUP"
	ResourceEBS          = "EBS_VOLUME"
ResourceIAM          = "IAM_USER"
)