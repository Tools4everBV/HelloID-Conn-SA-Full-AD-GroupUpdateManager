try {
    $searchValue = $formInput.searchValue
    $searchQuery = "*$searchValue*"
     
     
    if([String]::IsNullOrEmpty($searchValue) -eq $true){
        Hid-Add-TaskResult -ResultValue []
    }else{
        Hid-Write-Status -Message "SearchQuery: $searchQuery" -Event Information
        HID-Write-Summary -Message "Searching for: $searchQuery" -Event Information
        Hid-Write-Status -Message "SearchBase: $searchOUs" -Event Information
         
        $ous = $searchOUs | ConvertFrom-Json
     
        $groups = foreach($item in $ous) {
             Get-ADGroup -Filter {Name -like $searchQuery} -SearchBase $item.ou -properties *
        }
         
        $groups = $groups | Sort-Object -Property Name
        $resultCount = @($groups).Count
        Hid-Write-Status -Message "Result count: $resultCount" -Event Information
        HID-Write-Summary -Message "Result count: $resultCount" -Event Information
         
        if(@($groups).Count -gt 0){
         foreach($group in $groups)
            {
                $returnObject = @{name=$group.name; description=$group.description;}
                Hid-Add-TaskResult -ResultValue $returnObject
            }
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
    }
} catch {
    HID-Write-Status -Message "Error searching AD user [$searchValue]. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Error searching AD user [$searchValue]" -Event Failed
     
    Hid-Add-TaskResult -ResultValue []
}