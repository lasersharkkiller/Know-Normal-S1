Import-Module -Name ".\AlertsModules\Alerts_Main.psm1"
Import-Module -Name ".\NewProcsModules\UnverifiedProcs_Main.psm1"
Import-Module -Name ".\NewProcsModules\UnsignedWinProcs_Main.psm1"
Import-Module -Name ".\stringsBaseline\BaseLineStrings_with_Intezer.psm1"

Write-Host "Choose which function you would like to use:"
Write-Host "1) Alerts and Threats"
Write-Host "2) New Unverified Processes"
Write-Host "3) New Unsigned Windows Processes"
Write-Host "4) New Unsigned Linux Processes"
Write-Host "5) Baseline Strings from the Processes"

$functionChoice = Read-Host "Enter an option"
    
    if ($functionChoice -eq 1){
        Get-AlertsandThreatsFunction
    }
    elseif ($functionChoice -eq 2){
        Get-UnverifiedProcs
    }
    elseif ($functionChoice -eq 3){
        Get-UnsignedWinProcs
    }
    elseif ($functionChoice -eq 4){
        Get-UnsignedLinuxProcs
    }
    elseif ($functionChoice -eq 5){
        Get-StringsBaseline
    }
    else {
      Write-Host "You did not choose a valid option"
    }
