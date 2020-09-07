try {
    $adGroup = Get-ADgroup -Filter { Name -eq $groupName }
    HID-Write-Status -Message "Found AD group [$groupName]" -Event Information
    HID-Write-Summary -Message "Found AD group [$groupName]" -Event Information
} catch {
    HID-Write-Status -Message "Could not find AD group [$groupName]. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to find AD group [$groupName]" -Event Failed
}

try {
    $managerObject = Get-ADuser -Filter { UserPrincipalName -eq $managerUPN }
    HID-Write-Status -Message "Found AD user [$managerUPN]" -Event Information
    HID-Write-Summary -Message "Found AD user [$managerUPN]" -Event Information
} catch {
    HID-Write-Status -Message "Could not find AD user [$managerUPN]. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to find AD user [$managerUPN]" -Event Failed
}


try {
    Set-ADGroup -identity $adGroup -managedBy $managerObject
    
    HID-Write-Status -Message "Finished updated ManagedBy of [$groupName] to [$managerUPN]" -Event Success
    HID-Write-Summary -Message "Successfully updated ManagedBy of [$groupName] to [$managerUPN]" -Event Success
} catch {
    HID-Write-Status -Message "Could not update ManagedBy of [$groupName] to [$managerUPN]. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to update ManagedBy of [$groupName] to [$managerUPN]" -Event Failed
}