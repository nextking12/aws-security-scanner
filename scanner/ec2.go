package scanner

import (
    "aws-security-scanner/models"
    "fmt"
    
    "github.com/aws/aws-sdk-go/service/ec2"
)

/*
Security Group checks - looking for overly permissive rules

This is critical security checking! 0.0.0.0/0 means "the entire internet"
*/

// scanSecurityGroups checks EC2 security groups for issues
func (s *Scanner) scanSecurityGroups() error {
    // Create EC2 client
    svc := ec2.New(s.session)
    
    // Describe all security groups
    result, err := svc.DescribeSecurityGroups(nil)
    if err != nil {
        return fmt.Errorf("failed to describe security groups: %w", err)
    }
    
    fmt.Printf("  Found %d security groups\n", len(result.SecurityGroups))
    
    // Check each security group
    for _, sg := range result.SecurityGroups {
        s.checkSecurityGroupRules(sg)
    }
    
    return nil
}

/*
checkSecurityGroupRules examines ingress rules for issues

We're looking for rules that allow access from 0.0.0.0/0 (anywhere)
to sensitive ports like SSH (22), RDP (3389), databases, etc.

Java equivalent:
private void checkRules(SecurityGroup sg) {
    for (IpPermission perm : sg.getIpPermissions()) {
        for (IpRange range : perm.getIpv4Ranges()) {
            if ("0.0.0.0/0".equals(range.getCidrIp())) {
                // Critical finding!
            }
        }
    }
}
*/

// checkSecurityGroupRules checks for overly permissive rules
func (s *Scanner) checkSecurityGroupRules(sg *ec2.SecurityGroup) {
    sgID := *sg.GroupId
    sgName := *sg.GroupName
    
    // Check ingress (inbound) rules
    for _, permission := range sg.IpPermissions {
        // Get port range
        var fromPort, toPort int64
        if permission.FromPort != nil {
            fromPort = *permission.FromPort
        }
        if permission.ToPort != nil {
            toPort = *permission.ToPort
        }
        
        // Check each IP range in the rule
        for _, ipRange := range permission.IpRanges {
            cidr := *ipRange.CidrIp
            
            // Check if rule allows access from anywhere (0.0.0.0/0)
            if cidr == "0.0.0.0/0" {
                s.checkPublicAccess(sgID, sgName, fromPort, toPort)
            }
        }
    }
}

// checkPublicAccess creates findings for publicly accessible ports
func (s *Scanner) checkPublicAccess(sgID, sgName string, fromPort, toPort int64) {
    // Critical ports that should NEVER be public
    criticalPorts := map[int64]string{
        22:   "SSH",
        3389: "RDP",
        5432: "PostgreSQL",
        3306: "MySQL",
        1433: "SQL Server",
        27017: "MongoDB",
        6379: "Redis",
    }
    
    // Check if this is a critical port
    // Java: for (Map.Entry<Integer, String> entry : criticalPorts.entrySet()) { ... }
    for port, service := range criticalPorts {
        // Check if port is in range
        if port >= fromPort && port <= toPort {
            finding := models.NewCriticalFinding(
                sgID,
                models.ResourceSecurityGroup,
                fmt.Sprintf("%s Port Publicly Accessible", service),
                fmt.Sprintf("Security group '%s' (%s) allows %s access (port %d) "+
                    "from the entire internet (0.0.0.0/0). This is a critical security risk.",
                    sgName, sgID, service, port),
            )
            s.addFinding(finding)
        }
    }
    
    // Warn about any public access
    if fromPort == 0 && toPort == 65535 {
        finding := models.NewCriticalFinding(
            sgID,
            models.ResourceSecurityGroup,
            "All Ports Publicly Accessible",
            fmt.Sprintf("Security group '%s' (%s) allows ALL ports from anywhere. "+
                "This is extremely dangerous.", sgName, sgID),
        )
        s.addFinding(finding)
    }
}