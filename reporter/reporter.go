package reporter

import (
    "aws-security-scanner/models"
    "encoding/json"
    "fmt"
    "os"
    "sort"
    
    "github.com/fatih/color"
    "github.com/olekukonko/tablewriter"
)

/*
Reporter generates reports in different formats

Java equivalent:
@Service
public class ReportGenerator {
    public void printReport(List<Finding> findings) { ... }
    public String generateJSON(List<Finding> findings) { ... }
}
*/

// Reporter handles report generation
type Reporter struct {
    findings []*models.Finding
}

// NewReporter creates a new Reporter
func NewReporter(findings []*models.Finding) *Reporter {
    return &Reporter{
        findings: findings,
    }
}

/*
PrintConsole prints a nice terminal report with colors

Java equivalent:
public void printConsole() {
    System.out.println(ANSI_RED + "CRITICAL" + ANSI_RESET);
    // ...
}

Go's color library makes this much cleaner!
*/

// PrintConsole prints findings to terminal with colors
func (r *Reporter) PrintConsole() {
    if len(r.findings) == 0 {
        color.Green("\n✅ No security issues found!")
        return
    }
    
    // Print header
    fmt.Println("\n" + color.RedString("═══════════════════════════════════════════════════════════"))
    fmt.Println(color.RedString("                    SECURITY FINDINGS"))
    fmt.Println(color.RedString("═══════════════════════════════════════════════════════════"))
    
    // Group by severity
    bySeverity := r.groupBySeverity()
    
    // Print each severity group
    severities := []string{
        models.SeverityCritical,
        models.SeverityHigh,
        models.SeverityMedium,
        models.SeverityLow,
    }
    
    for _, severity := range severities {
        findings := bySeverity[severity]
        if len(findings) == 0 {
            continue
        }
        
        // Print severity header with color
        fmt.Printf("\n%s (%d findings)\n", r.coloredSeverity(severity), len(findings))
        fmt.Println(color.WhiteString("─────────────────────────────────────────────────────────────"))
        
        // Print each finding
        for i, finding := range findings {
            fmt.Printf("\n%d. %s\n", i+1, color.YellowString(finding.Title))
            fmt.Printf("   Resource: %s (%s)\n", finding.ResourceID, finding.ResourceType)
            fmt.Printf("   Region: %s\n", finding.Region)
            fmt.Printf("   %s\n", finding.Description)
        }
    }
    
    // Print summary
    fmt.Println("\n" + color.RedString("═══════════════════════════════════════════════════════════"))
    r.printSummary()
}

/*
PrintTable prints findings as an ASCII table

Java equivalent: Using a library like ASCII Table Generator
*/

// PrintTable prints findings in table format
func (r *Reporter) PrintTable() {
    if len(r.findings) == 0 {
        color.Green("\n✅ No security issues found!")
        return
    }
    
    // Create table
    table := tablewriter.NewWriter(os.Stdout)
    table.SetHeader([]string{"Severity", "Resource Type", "Resource ID", "Title"})
    
    // Configure table appearance
    table.SetBorder(true)
    table.SetRowLine(true)
    table.SetAutoWrapText(false)
    
    // Add rows
    for _, finding := range r.findings {
        row := []string{
            finding.Severity,
            finding.ResourceType,
            finding.ResourceID,
            finding.Title,
        }
        table.Append(row)
    }
    
    fmt.Println()
    table.Render()
    r.printSummary()
}

/*
GenerateJSON exports findings as JSON

Java equivalent (using Jackson):
ObjectMapper mapper = new ObjectMapper();
String json = mapper.writerWithDefaultPrettyPrinter()
    .writeValueAsString(findings);
*/

// GenerateJSON returns findings as JSON string
func (r *Reporter) GenerateJSON() (string, error) {
    // Marshal to JSON with indentation
    // Java: mapper.writeValueAsString(findings)
    jsonData, err := json.MarshalIndent(r.findings, "", "  ")
    if err != nil {
        return "", fmt.Errorf("failed to marshal JSON: %w", err)
    }
    
    return string(jsonData), nil
}

// SaveJSON writes findings to JSON file
func (r *Reporter) SaveJSON(filename string) error {
    jsonStr, err := r.GenerateJSON()
    if err != nil {
        return err
    }
    
    // Write to file
    // Java: Files.writeString(Path.of(filename), json);
    return os.WriteFile(filename, []byte(jsonStr), 0644)
}

// Helper functions

// groupBySeverity groups findings by severity level
func (r *Reporter) groupBySeverity() map[string][]*models.Finding {
    // Create map (like HashMap in Java)
    groups := make(map[string][]*models.Finding)
    
    // Initialize each severity
    groups[models.SeverityCritical] = make([]*models.Finding, 0)
    groups[models.SeverityHigh] = make([]*models.Finding, 0)
    groups[models.SeverityMedium] = make([]*models.Finding, 0)
    groups[models.SeverityLow] = make([]*models.Finding, 0)
    
    // Group findings
    for _, finding := range r.findings {
        groups[finding.Severity] = append(groups[finding.Severity], finding)
    }
    
    return groups
}

// coloredSeverity returns severity with appropriate color
func (r *Reporter) coloredSeverity(severity string) string {
    switch severity {
    case models.SeverityCritical:
        return color.RedString("🔴 CRITICAL")
    case models.SeverityHigh:
        return color.HiRedString("🟠 HIGH")
    case models.SeverityMedium:
        return color.YellowString("🟡 MEDIUM")
    case models.SeverityLow:
        return color.BlueString("🔵 LOW")
    default:
        return severity
    }
}

// printSummary prints finding count summary
func (r *Reporter) printSummary() {
    bySeverity := r.groupBySeverity()
    
    fmt.Println("\nSummary:")
    fmt.Printf("  Total Findings: %d\n", len(r.findings))
    fmt.Printf("  Critical: %d\n", len(bySeverity[models.SeverityCritical]))
    fmt.Printf("  High: %d\n", len(bySeverity[models.SeverityHigh]))
    fmt.Printf("  Medium: %d\n", len(bySeverity[models.SeverityMedium]))
    fmt.Printf("  Low: %d\n", len(bySeverity[models.SeverityLow]))
    fmt.Println()
}

// SortBySeReporter

// SortBySeverity sorts findings by severity (critical first)
func (r *Reporter) SortBySeverity() {
    // Define severity order
    severityOrder := map[string]int{
        models.SeverityCritical: 0,
        models.SeverityHigh:     1,
        models.SeverityMedium:   2,
        models.SeverityLow:      3,
    }
    
    // Sort slice
    // Java: Collections.sort(findings, comparator);
    sort.Slice(r.findings, func(i, j int) bool {
        return severityOrder[r.findings[i].Severity] < severityOrder[r.findings[j].Severity]
    })
}