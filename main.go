package main

import (
    "aws-security-scanner/reporter"
    "aws-security-scanner/scanner"
    "flag"
    "fmt"
    "os"
    
    "github.com/fatih/color"
)

/*
Main entry point - like Application.java in Spring Boot

Java equivalent:
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

In Go, main() is always the entry point.
*/

func main() {
    // Parse command-line flags
    // Java: Using @CommandLineRunner or Apache Commons CLI
    region := flag.String("region", "us-east-1", "AWS region to scan")
    output := flag.String("output", "console", "Output format: console, table, json")
    jsonFile := flag.String("file", "", "Output JSON file (when output=json)")
    concurrent := flag.Bool("concurrent", false, "Run scans concurrently")
    
    flag.Parse()
    
    // Print banner
    printBanner()
    
    // Create scanner
    s, err := scanner.NewScanner(*region)
    if err != nil {
        color.Red("❌ Error creating scanner: %v", err)
        os.Exit(1)
    }
    
    // Run scan
    if *concurrent {
        err = s.ScanConcurrent()
    } else {
        err = s.Scan()
    }
    
    if err != nil {
        color.Red("❌ Scan failed: %v", err)
        os.Exit(1)
    }
    
    // Get findings
    findings := s.GetFindings()
    
    // Generate report
    rep := reporter.NewReporter(findings)
    rep.SortBySeverity()
    
    // Output based on format
    switch *output {
    case "console":
        rep.PrintConsole()
    case "table":
        rep.PrintTable()
    case "json":
        if *jsonFile == "" {
            // Print to stdout
            jsonStr, err := rep.GenerateJSON()
            if err != nil {
                color.Red("❌ Error generating JSON: %v", err)
                os.Exit(1)
            }
            fmt.Println(jsonStr)
        } else {
            // Save to file
            if err := rep.SaveJSON(*jsonFile); err != nil {
                color.Red("❌ Error saving JSON: %v", err)
                os.Exit(1)
            }
            color.Green("✅ Report saved to: %s", *jsonFile)
        }
    default:
        color.Red("❌ Unknown output format: %s", *output)
        os.Exit(1)
    }
    
    // Exit with error code if critical findings exist
    critical := s.GetCriticalFindings()
    if len(critical) > 0 {
        os.Exit(1) // Non-zero exit for CI/CD pipelines
    }
}

func printBanner() {
    banner := `
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║          AWS SECURITY SCANNER                         ║
    ║          Automated Security Assessment                ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    `
    color.Cyan(banner)
}