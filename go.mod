module aws-security-scanner
// go.mod is like pom.xml - declares dependencies
// Create this by running: go mod init aws-security-scanner

go 1.24.0

require (
    github.com/aws/aws-sdk-go v1.49.0  // AWS SDK (like AWS SDK for Java)
    github.com/fatih/color v1.16.0     // Colored terminal output
    github.com/olekukonko/tablewriter v0.0.5  // ASCII tables
)