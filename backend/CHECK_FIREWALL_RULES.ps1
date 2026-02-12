# ========================================
# Check ThreatGuard Firewall Rules
# ========================================
# This script displays all firewall rules created by ThreatGuard
# ========================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ThreatGuard Firewall Rules" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check for ThreatGuard rules
Write-Host "Searching for ThreatGuard firewall rules..." -ForegroundColor Yellow
Write-Host ""

$rules = netsh advfirewall firewall show rule name=all | Select-String "ThreatGuard"

if ($rules) {
    Write-Host "Found ThreatGuard rules:" -ForegroundColor Green
    Write-Host ""
    
    # Get all rules with ThreatGuard in the name
    $allRules = netsh advfirewall firewall show rule name=all
    
    # Filter and display ThreatGuard rules
    $inThreatGuardRule = $false
    foreach ($line in $allRules) {
        if ($line -match "Rule Name:\s+ThreatGuard") {
            $inThreatGuardRule = $true
            Write-Host "----------------------------------------" -ForegroundColor Cyan
        }
        
        if ($inThreatGuardRule) {
            Write-Host $line
            
            # End of rule section
            if ($line -match "^$" -or $line -match "^-+$") {
                $inThreatGuardRule = $false
            }
        }
    }
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    
} else {
    Write-Host "No ThreatGuard firewall rules found." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "This could mean:" -ForegroundColor Yellow
    Write-Host "  - No IPs have been blocked yet" -ForegroundColor Yellow
    Write-Host "  - Backend is not running with Administrator privileges" -ForegroundColor Yellow
    Write-Host "  - Firewall rules were manually removed" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host ""
Write-Host "To view ALL firewall rules:" -ForegroundColor Cyan
Write-Host "  netsh advfirewall firewall show rule name=all" -ForegroundColor White
Write-Host ""

Pause
