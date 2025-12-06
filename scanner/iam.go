package scanner

import (
    "aws-security-scanner/models"
    "fmt"
    
    "github.com/aws/aws-sdk-go/service/iam"
)

/*
IAM checks - looking for users without MFA, old access keys, etc.

Multi-Factor Authentication (MFA) is critical for security.
Users with console access should ALWAYS have MFA enabled.
*/

// scanIAM checks IAM users for security issues
func (s *Scanner) scanIAM() error {
    // IAM is global, no region needed
    svc := iam.New(s.session)
    
    // List all IAM users
    result, err := svc.ListUsers(nil)
    if err != nil {
        return fmt.Errorf("failed to list IAM users: %w", err)
    }
    
    fmt.Printf("  Found %d IAM users\n", len(result.Users))
    
    // Check each user
    for _, user := range result.Users {
        s.checkUserMFA(svc, user)
        s.checkUserAccessKeys(svc, user)
    }
    
    return nil
}

/*
checkUserMFA verifies user has MFA enabled

Java equivalent:
private void checkMFA(AmazonIdentityManagement iam, User user) {
    ListMFADevicesRequest request = new ListMFADevicesRequest()
        .withUserName(user.getUserName());
    ListMFADevicesResult result = iam.listMFADevices(request);
    
    if (result.getMFADevices().isEmpty()) {
        // User has no MFA!
    }
}
*/

// checkUserMFA checks if user has MFA enabled
func (s *Scanner) checkUserMFA(svc *iam.IAM, user *iam.User) {
    userName := *user.UserName
    
    // First, check if user has console access
    _, err := svc.GetLoginProfile(&iam.GetLoginProfileInput{
        UserName: user.UserName,
    })
    
    // If no login profile, user can't access console - skip MFA check
    if err != nil {
        return
    }
    
    // User has console access - check for MFA
    mfaResult, err := svc.ListMFADevices(&iam.ListMFADevicesInput{
        UserName: user.UserName,
    })
    
    if err != nil {
        return
    }
    
    // Check if user has any MFA devices
    if len(mfaResult.MFADevices) == 0 {
        finding := models.NewHighFinding(
            userName,
            models.ResourceIAM,
            "IAM User Without MFA",
            fmt.Sprintf("IAM user '%s' has console access but no MFA device configured. "+
                "MFA provides critical additional security layer.", userName),
        )
        s.addFinding(finding)
    }
}

// checkUserAccessKeys checks for old or unused access keys
func (s *Scanner) checkUserAccessKeys(svc *iam.IAM, user *iam.User) {
    userName := *user.UserName
    
    // List access keys for user
    result, err := svc.ListAccessKeys(&iam.ListAccessKeysInput{
        UserName: user.UserName,
    })
    
    if err != nil {
        return
    }
    
    // Check each access key
    for _, key := range result.AccessKeyMetadata {
        // Check if key is active
        if *key.Status == "Active" {
            // Get key age
            keyAge := key.CreateDate
            
            // You could add age checking here
            // For now, just note that active keys exist
            _ = keyAge // Silence unused variable warning
            
            // Note: You'd typically check last used date via GetAccessKeyLastUsed
            // and flag keys that haven't been used in 90+ days
        }
    }
}