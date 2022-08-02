$groupName = $form.gridGroups.name
$managerUPN = $form.managedBy.UserPrincipalName

try {
    $adGroup = Get-ADgroup -Filter { Name -eq $groupName }
    Write-Information "Found AD group [$groupName]"    
} catch {
    Write-Error "Could not find AD group [$groupName]. Error: $($_.Exception.Message)"
}

try {
    $managerObject = Get-ADuser -Filter { UserPrincipalName -eq $managerUPN }
    Write-Information "Found AD user [$managerUPN]"    
} catch {
    Write-Error "Could not find AD user [$managerUPN]. Error: $($_.Exception.Message)"
}

try {
    Set-ADGroup -identity $adGroup -managedBy $managerObject    
    Write-Information "Finished updated ManagedBy of [$groupName] to [$managerUPN]"
    $Log = @{
        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
        System            = "ActiveDirectory" # optional (free format text) 
        Message           = "Successfully updated ManagedBy of [$groupName] to [$managerUPN]" # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $groupName # optional (free format text) 
        TargetIdentifier  = $([string]$adGroup.SID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log    
} catch {
    Write-Error "Could not update ManagedBy of [$groupName] to [$managerUPN]. Error: $($_.Exception.Message)"
    $Log = @{
        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
        System            = "ActiveDirectory" # optional (free format text) 
        Message           = "Failed to update ManagedBy of [$groupName] to [$managerUPN]" # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $groupName # optional (free format text) 
        TargetIdentifier  = $([string]$adGroup.SID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log    
}
