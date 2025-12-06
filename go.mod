module aws-security-scanner

// go.mod is like pom.xml - declares dependencies
// Create this by running: go mod init aws-security-scanner

go 1.24.0

require (
	github.com/aws/aws-sdk-go v1.49.0 // AWS SDK (like AWS SDK for Java)
	github.com/fatih/color v1.16.0 // Colored terminal output
	github.com/olekukonko/tablewriter v0.0.5 // ASCII tables
)

require (
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.9 // indirect
	golang.org/x/sys v0.14.0 // indirect
)
