###################################################################################
### This script will add Solarwinds TI to Azure Sentinel by using the Graph API ###
###################################################################################

# Make sure an app registration is created with permissions on the Graph API: ThreatIndicators.ReadWrite.OwnedBy. Admin Concent is needed.
$ClientId = ''
$TenantId = ''
$Secret = ''


# Create a hashtable for the body, the data needed for the token request
# The variables used are explained above
$Body = @{
    'tenant' = $TenantId
    'client_id' = $ClientId
    'scope' = 'https://graph.microsoft.com/.default'
    'client_secret' = $Secret
    'grant_type' = 'client_credentials'
}

# Assemble a hashtable for splatting parameters, for readability
# The tenant id is used in the uri of the request as well as the body
$Params = @{
    'Uri' = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    'Method' = 'Post'
    'Body' = $Body
    'ContentType' = 'application/x-www-form-urlencoded'
}

$AuthResponse = Invoke-RestMethod @Params

$Headers = @{
    'Authorization' = "Bearer $($AuthResponse.access_token)"
}

## Download the indicators from the Microsoft Github
$request = 'https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/MSTICIoCs-ExchangeServerVulnerabilitiesDisclosedMarch2021.json'
$requestData = Invoke-WebRequest $request 
$data = ConvertFrom-Json $requestData

$filepaths = $data | Where-Object {$_.IndicatorType -eq 'filepath'}
$sha256hashes = $data | Where-Object {$_.IndicatorType -eq 'sha256'}

## Insert indicators into AzureSentinel
foreach($filepath in $filepaths) {
    foreach($sha256hash in $sha256hashes) {
      $Indicator = @{
        'action' = "alert"
        'filePath' = $item.Indicator
        'fileHashType' = 'sha256'
        'fileHashValue' = $sha256hash.Indicator
        'description' = "IOC March 2021 Exchange vulnerability"
        'confidence' = '100'
        'targetProduct' = "Azure Sentinel"
        'azureTenantId' = $TenantId
        'expirationDateTime' = "2021-06-01T00:00:00Z"
        'threatType' = 'Malware'
        'tlpLevel' = 'white'
      }
      
      $indicatorJson = $Indicator | ConvertTo-Json
      $Result = Invoke-RestMethod -Method 'Post' -Uri 'https://graph.microsoft.com/beta/security/tiIndicators' -Headers $Headers -Body $indicatorJson
      $Result
    }
}

# Display the result
$Result = Invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/security/tiIndicators' -Headers $Headers
