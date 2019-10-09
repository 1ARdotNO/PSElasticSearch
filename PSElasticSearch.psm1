function Get-Elasticdata{
    param(
    $index,
    $body,
    $server,
    [string]$port="9200",
    [switch]$scroll,
    $size=100,
    $simplequery
    )
    
    if($scroll){
        #Send query and get scroll id for retrieval
        if ($simplequery -and !$body){ #if check for simple or complex query
            $scrollrequest=Invoke-RestMethod -Uri "http://$server`:$port/$index/_search/?q=$simplequery&scroll=1m" -Method get -ContentType 'application/json'
        }else{
            $scrollrequest=Invoke-RestMethod -Uri "http://$server`:$port/$index/_search/?scroll=1m" -Body $body -Method post -ContentType 'application/json'
        }
        
        #build object for scroll result retrival
        $scrollgetbody=[pscustomobject]@{
            scroll = "1m"
            scroll_id = "$($scrollrequest._scroll_id)"
        } | ConvertTo-Json
        #loop all scroll results
        do{
            $scrollreqresult=$null #reset variable so that end of results can be detected
            $scrollreqresult=Invoke-RestMethod -Uri "http://$server`:$port/_search/scroll" -Body $scrollgetbody -Method post -ContentType 'application/json' #get scroll results 10 at a time
            $scrollreqresult #output scroll results
        }while($scrollreqresult.hits.hits)#loop to output scroll results while there are results being delivered by elastic
    }
    else{ #If no scroll do query and return specified number of results
        if ($simplequery -and !$body){ #if check for simple or complex query
            Invoke-RestMethod -Uri "http://$server`:$port/$index/_search/?q=$simplequery&size=$size" -Method get -ContentType 'application/json'
        }else{
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
    
    switch($inputtype){
    
        netflow {
            switch($resulttype){
                toptalkers {
                    $item.aggregations.source.buckets | ForEach-Object {
                        [pscustomobject]@{
                            host = $_.key
                            totalbytes = $_.totalbytes.value
                        }
                    }
                }
            }
        }
    
    }
    
}