Connect-AzureAD

$miObjectID = $null
Write-Host "Looking for Managed Identity with default name of the Logic App..."
$miObjectID = (Get-AzureADServicePrincipal -SearchString "Import-AADSCAtoLAWS").ObjectId
if ($miObjectID -eq $null) {
   $miObjectID = Read-Host -Prompt "Enter ObjectId of Managed Identity (from Logic App):"
}

# The app ID of the Microsoft Graph API where we want to assign the permissions
$appId = "00000003-0000-0000-c000-000000000000"


$permissionsToAdd = @("Policy.Read.All", "ConsentRequest.Read.All", "Directory.Read.All","ServicePrincipalEndpoint.Read.All","Directory.AccessAsUser.All","Policy.Read.PermissionGrant")

$app = Get-AzureADServicePrincipal -Filter "AppId eq '$appId'"

foreach ($permission in $permissionsToAdd)
{
   Write-Host $permission
   $role = $app.AppRoles | where Value -Like $permission | Select-Object -First 1
   New-AzureADServiceAppRoleAssignment -Id $role.Id -ObjectId $miObjectID -PrincipalId $miObjectID -ResourceId $app.ObjectId
}