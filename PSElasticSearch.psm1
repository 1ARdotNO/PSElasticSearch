function Get-Elasticdata {
    param(
        $index,
        $body,
        $server,
        [string]$port = "9200",
        [switch]$scroll,
        [switch]$count,
        $size = 100,
        $simplequery
    )
    
    if ($scroll) {
        #Send query and get scroll id for retrieval
        if ($simplequery -and !$body) {
            #if check for simple or complex query
            $scrollrequest = Invoke-RestMethod -Uri "http://$server`:$port/$index/_search/?q=$simplequery&scroll=1m" -Method get -ContentType 'application/json'
        }
        else {
            $scrollrequest = Invoke-RestMethod -Uri "http://$server`:$port/$index/_search/?scroll=1m" -Body $body -Method post -ContentType 'application/json'
        }
        
        #build object for scroll result retrival
        $scrollgetbody = [pscustomobject]@{
            scroll    = "1m"
            scroll_id = "$($scrollrequest._scroll_id)"
        } | ConvertTo-Json
        #loop all scroll results
        #output hits from initial request
        
        [System.Collections.Generic.List[Object]]$_scroll_id += $scrollrequest._scroll_id
        [System.Collections.Generic.List[Object]]$timed_out += $scrollrequest.timed_out.tostring()
        [System.Collections.Generic.List[Object]]$_shards += $scrollrequest._shards
        [System.Collections.Generic.List[Object]]$hits += $scrollrequest.hits
        [System.Collections.Generic.List[Object]]$aggregations += $scrollrequest.aggregations
        [int]$took += [int]$scrollreqresult.took #temp to calculate total time

        do {
            #$scrollreqresult=$null #reset variable so that end of results can be detected
            $scrollreqresult = Invoke-RestMethod -Uri "http://$server`:$port/_search/scroll" -Body $scrollgetbody -Method post -ContentType 'application/json' #get scroll results 10 at a time
            
            $_scroll_id += $scrollreqresult._scroll_id
            $timed_out += $scrollreqresult.timed_out.tostring()
            $_shards += $scrollreqresult._shards
            $hits += $scrollreqresult.hits
            [int]$took += [int]$scrollreqresult.took #temp to calculate total time


            #$scrollreqresult #output scroll results
            
        }while ($scrollreqresult.hits.hits)#loop to output scroll results while there are results being delivered by elastic
        [pscustomobject]@{
            _scroll_id   = $_scroll_id
            took         = $took
            timed_out    = $timed_out
            _shards      = $_shards
            hits         = $hits
            aggregations = $aggregations
        }
        
    }
    elseif ($count) {
        #If count do query and return count
        if ($simplequery -and !$body) {
            #if check for simple or complex query
            Invoke-RestMethod -Uri "http://$server`:$port/$index/_count/?q=$simplequery" -Method get -ContentType 'application/json'
        }
        else {
            Invoke-RestMethod -Uri "http://$server`:$port/$index/_count/" -Body $body -Method post -ContentType 'application/json'
        }
    }
    else {
        #If no scroll do query and return specified number of results
        if ($simplequery -and !$body) {
            #if check for simple or complex query
            Invoke-RestMethod -Uri "http://$server`:$port/$index/_search/?q=$simplequery&size=$size" -Method get -ContentType 'application/json'
        }
        else {
            Invoke-RestMethod -Uri "http://$server`:$port/$index/_search/?size=$size" -Body $body -Method post -ContentType 'application/json'
        }
    }
    
}

function Convert-Elasticdata {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$item,
        $inputtype,
        $resulttype
    )
    
    switch ($inputtype) {
    
        netflow {
            switch ($resulttype) {
                toptalkers {
                    $item.aggregations.source.buckets | ForEach-Object {
                        [pscustomobject]@{
                            Host      = $_.key
    
                            Megabytes = [math]::round($_.totalbytes.value / 1MB, 0)
                        }
                    }
                }
                topprotocols {
                    $item.aggregations.source.buckets | ForEach-Object {
                        [pscustomobject]@{
                            Protocol  = $_.key
    
                            Megabytes = [math]::round($_.totalbytes.value / 1MB, 0)
                        }
                    }
                }
            }
        }
        pfsense {
            switch ($resulttype) {
                failedlogons {
                    $logon = $item.hits.hits._source | where { $_.message -like "*authentication error*" }
                    $failedlogons = $logon | ForEach-Object {
                        [pscustomobject]@{
                            username  = $_.pfsense_USER
                            source_IP = $_.message.split(":")[2]
                        }
                    }
                    $failedlogons.username | sort | Get-Unique | ForEach-Object {
                        $tinput = $_
                        [pscustomobject]@{
                            username  = $_
                            source_IP = ($failedlogons | where { $_.username -eq $tinput }).source_IP | Get-Unique
                            attempts  = ($failedlogons | where { $_.username -eq $tinput }).count
                        }
                    }
                }
                openvpnfailedlogons {
                    $logon = $item.hits.hits._source
                    $logon | ForEach-Object {
                        [pscustomobject]@{
                            username = $_.message.split("'")[1]
                            time     = $_."@timestamp" | get-date
                        }
                    }
                
                }
                firewallblocktop {
                    $item.aggregations.source.buckets | foreach-object {
                        [PSCustomObject]@{
                            IP       = $_.key
                            Attempts = $_.doc_count
                        }
                    }
                }
            }
        }
        windows {
            switch ($resulttype) {
                failedlogons {
                    $events = $item.hits.hits._source | ForEach-Object {
                        [pscustomobject]@{
                            Username = $_.event_data.targetusername
                            Time     = ($_."@timestamp" | get-date -Format "dd.MM.yyyy HH:mm:ss").ToString()
                        }
                    }
                    $uniquevents = $events | sort time | Get-Unique -AsString
                    #totalcount
                    [pscustomobject]@{
                        Username          = "Total"
                        "Failed attempts" = $uniquevents.count
                    }
                    $uniquevents.username | sort | get-unique -asstring | ForEach-Object {
                        $tinput = $_
                        $count = ($uniquevents | where { $_.username -eq $tinput }).count
                        if (!$count) { $count = 1 } #For error where 1 count is recorded as NULL
                        [pscustomobject]@{
                            Username          = $_
                            "Failed attempts" = $count
                        }
                    } | sort "Failed attempts" -Descending
                }
                fileDLP {
                    $item.hits.hits._source | ForEach-Object {
                        [pscustomobject]@{
                            user  = $_.event_data.SubjectUserName
                            path  = $_.event_data.ObjectName
                            time  = "$($_."@timestamp" | get-date)"
                            audit = $_.keywords.replace("Audit ", "")
                        }
                    } | sort $_.path | Get-Unique -AsString
                }
                fsPerms {
                    $item.hits.hits._source | ForEach-Object {
                        $OldACLObject = New-Object -TypeName System.Security.AccessControl.DirectorySecurity
                        $OldACLObject.SetSecurityDescriptorSddlForm($_.event_data.oldsd)
                        $NewACLObject = New-Object -TypeName System.Security.AccessControl.DirectorySecurity
                        $NewACLObject.SetSecurityDescriptorSddlForm($_.event_data.newsd)
                        [PSCustomObject]@{
                            Changedby = $_.event_data.subjectusername
                            Item      = $_.event_data.ObjectName
                            OldPerms  = $OldACLObject
                            NewPerms  = $NewACLObject
                            Diff      = $newaclobject.AccessToString.split([Environment]::NewLine) | foreach-object {
                                $_ | where { $oldaclobject.AccessToString.split([Environment]::NewLine) -notcontains $_ }
                            }
                        }
                    }
                }
                adchanges {
                    $item.hits.hits._source | ForEach-Object {
                        [pscustomobject]@{
                            Time       = ($_."@timestamp" | get-date).tostring()
                            Changedby  = $_.event_data.subjectusername
                            TargetUser = if ($_.event_data.oldtargetusername) { "$($_.event_data.oldtargetusername)->$($_.event_data.newtargetusername)" }else { $_.event_data.targetusername }
                            EventID    = $_.event_id
                            Reason     = $_.message.split([Environment]::NewLine)[0]
                            
                        }
                    }
                }
            }
        }
        
    
    }
     
}


