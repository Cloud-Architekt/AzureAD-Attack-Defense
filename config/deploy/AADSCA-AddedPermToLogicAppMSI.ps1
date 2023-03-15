
# Replace with your managed identity object ID
$miObjectID = "object id here"

# The app ID of the API where you want to assign the permissions
$appId = "00000003-0000-0000-c000-000000000000"

# The app IDs of the Microsoft APIs are the same in all tenants:
# Microsoft Graph: 00000003-0000-0000-c000-000000000000
# SharePoint Online: 00000003-0000-0ff1-ce00-000000000000

# Replace with the API permissions required by your app

# Device management config permission not required at the moment
#$permissionsToAdd = @("Policy.Read.All", "ConsentRequest.Read.All", "Directory.Read.All","DeviceManagementConfiguration.Read.All")

$permissionsToAdd = @("Policy.Read.All", "ConsentRequest.Read.All", "Directory.Read.All")
$permissionsToAdd += @("ServicePrincipalEndpoint.Read.All")
$permissionsToAdd += @("Directory.AccessAsUser.All")
$permissionsToAdd += @("Policy.Read.PermissionGrant")

#Connect-AzureAD

$app = Get-AzureADServicePrincipal -Filter "AppId eq '$appId'"

foreach ($permission in $permissionsToAdd)
{
   Write-Host $permission
   $role = $app.AppRoles | where Value -Like $permission | Select-Object -First 1
   New-AzureADServiceAppRoleAssignment -Id $role.Id -ObjectId $miObjectID -PrincipalId $miObjectID -ResourceId $app.ObjectId
}