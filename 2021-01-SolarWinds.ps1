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

# Create an array conaining all the domains that need to be ingested as TI.
$Domains = @('avsvmcloud.com', 
             'databasegalore.com', 
             'deftsecurity.com', 
             'digitalcollege.com', 
             'freescanonline.com', 
             'globalnetworkissues.com', 
             'highdatabase.com',
             'incomeupdate.com',
             'kubecloud.com',
             'lcomputers.com',
             'mobilnweb.com',
             'panhardware.com',
             'seobundlekit.com',
             'solartrackingsystem.net',
             'thedoccloud.com',
             'virtualwebdata.com',
             'webcodez.com',
             'websitetheme.com',
             'zupertech.com')

# Loop trough the array with domains, and create a TI item for each domain.
foreach($domain in $Domains) {
  $Indicator = @{
    'action' = "alert"
    'domainName' = $domain
    'description' = "Observed during various attacks"
    'confidence' = '80'
    'targetProduct' = "Azure Sentinel"
    'azureTenantId' = $TenantId
    'expirationDateTime' = "2021-06-01T00:00:00Z"
    'threatType' = 'Botnet'
    'tlpLevel' = 'Green'
  }
  $indicatorJson = $Indicator | ConvertTo-Json
  
  $Result = Invoke-RestMethod -Method 'Post' -Uri 'https://graph.microsoft.com/beta/security/tiIndicators' -Headers $Headers -Body $indicatorJson
  $Result
}

# Display the result
$Result = Invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/security/tiIndicators' -Headers $Headers