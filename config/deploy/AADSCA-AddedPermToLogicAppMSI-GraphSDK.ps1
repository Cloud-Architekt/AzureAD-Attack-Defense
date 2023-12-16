# Install required module
Install-Module Microsoft.Graph -Scope CurrentUser

# Connect to Graph
Connect-MgGraph -Scopes Application.Read.All, AppRoleAssignment.ReadWrite.All, RoleManagement.ReadWrite.Directory

# Object ID of AADSCA Logic App Managed Identity
$MiObjectIDs = @()
$MiObjectIDs = (Get-MgServicePrincipal -Filter "startswith(DisplayName, 'Import-AADSCA')").Id
if ($MiObjectIDs -eq $null) {
   $MiObjectIDs = Read-Host -Prompt "Enter ObjectId of Managed Identity (from Logic App):"
}

# Required permissions on Microsoft Graph for AADDSCA
$PermissionsToAdd = @("Policy.Read.All", "ConsentRequest.Read.All", "Directory.Read.All","ServicePrincipalEndpoint.Read.All","Policy.Read.PermissionGrant","DirectoryRecommendations.Read.All")

# Map required App Role Names to App Role IDs
$MsGraph = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"
$Roles = $MsGraph.AppRoles | Where-Object {$_.Value -in $PermissionsToAdd} 

# Assign Graph API permissions to every Managed Identity of an AADSCA Logic App
foreach ($miObjectID in $miObjectIDs) {
    foreach ($Role in $Roles) {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MiObjectID -PrincipalId $MiObjectID -ResourceId $MsGraph.Id -AppRoleId $Role.Id
    } 
}
Disconnect-MgGraph
