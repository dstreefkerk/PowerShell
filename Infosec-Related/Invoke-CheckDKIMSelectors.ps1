PARAM (
	[Parameter(Mandatory = $true, HelpMessage = "Specify a DNS Name to query for")]
	[ValidateNotNull()]
	[string]$EmailDomain
)

function Resolve-DoHDNSName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Specify a DNS Name to query for")]
	    [ValidateNotNull()]
	    [string]$Name,

        [Parameter(Mandatory = $false, HelpMessage = "Type of DNS record to query for. Defaults to an 'A' Record")]
	    [ValidateSet("A", "TXT", "MX", "SOA", "CNAME", IgnoreCase = $true)]
	    [string]$Type = "A"
    )
    
    # Cloudflare DNS over HTTPS endpoint URI
    $dohEndpoint = "https://cloudflare-dns.com/dns-query"

    try {
        $dnsResponse = Invoke-RestMethod -Uri "$($dohEndpoint)?name=$($Name)&type=$($Type)" -Headers @{'accept' = 'application/dns-json'}
        
        if ($dnsResponse.Answer) {
            $dnsResponse.Answer
        } 
    }
    catch {
        Write-Error "An error occurred while trying to query DNS over HTTPs for $Name"
    }
}

# Inspired by https://www.usenix.org/conference/usenixsecurity22/presentation/wang-chuhans
$dkimSelectors = "20150623","default","dkim","google","google2","k1","k2","k3","key1","key2","m1","m2","mail","s1","s2","selector1","selector2","tvdnhvr","zplfznz"
$matchedTXTSelectors = @()
$matchedCNAMESelectors = @()

foreach ($selector in $dkimSelectors) {
    $txtResult = Resolve-DoHDNSName -Name "$($selector)._domainkey.$($EmailDomain)" -Type TXT
    if (($txtResult) -and ($txtResult.data -match ".*v=DKIM1.*")){
        $matchedTXTSelectors += $selector
    }

    $cnameResult = Resolve-DoHDNSName -Name "$($selector)._domainkey.$($EmailDomain)" -Type CNAME
    if (($cnameResult) -and ($cnameResult.data -match ".*v=DKIM1.*")){
        $matchedCNAMESelectors +=$selector
    }
}

[PSCustomObject]@{
    "DKIMSelectors-TXT" = $matchedTXTSelectors -join ','
    "DKIMSelectors-CNAME" = $matchedCNAMESelectors -join ','
}