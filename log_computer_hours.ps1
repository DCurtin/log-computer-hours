function main
{
    $daysOfLogs = 5;

    $logPath = "C:\Users\dcurtin\logged_Computers.txt"
    Write-Output "logs starting on $(get-date)" > $logPath;

    [System.Collections.ArrayList]$combinedComputers = getAllComputers;

    $processedMap = processComputersWithForwardEvents -listOfComputers $combinedComputers -daysOfLogs $daysOfLogs -logPath $logPath;
    
    $newRecords = $(generateSFRecords -records $processedMap -json $false);
    
    $oldRecords = querySFRecords -daysOfRecords $daysOfLogs;
    
    $prunedRecords = $(removeLesserHours -oldRecords $oldRecords -newRecords $newRecords) | ConvertTo-Csv -NoTypeInformation;

    Write-Output "Updating $prunedRecords.Count" >> $logPath
    
    [IO.File]::WriteAllLines('C:\users\dcurtin\ComputerLogs__c.csv', $prunedRecords);
    sfdx force:data:bulk:upsert -s computerlog__c -f 'C:\users\dcurtin\ComputerLogs__c.csv' -i Name -u dcurtin@midlandira.com.dcurtin;
}

function getAllComputers
{
    [System.Collections.ArrayList]$adComputersFL = getADComputers -OULocaction "Fort Myers";
    [System.Collections.ArrayList]$adComputersSD = getADComputers -OULocaction "External-Shared";
    [System.Collections.ArrayList]$adComputersIL = getADComputers -OULocaction "Chicago";
    #[System.Collections.ArrayList]$adComputerAdmin = getADComputers -OULocaction "Administrators";
    
    [System.Collections.ArrayList]$combinedComputers = @();
    
    $combinedComputers.AddRange($adComputersFL);
    $combinedComputers.AddRange($adComputersSD);
    $combinedComputers.AddRange($adComputersIL);
    $combinedComputers.AddRange($adComputerAdmin);
    
    return $combinedComputers; 
}

function getADComputers
{
    param
    (
        [string]$OULocaction
    )

    [System.Collections.ArrayList] $domainComputers = @();
    Get-ADComputer -Properties @("Name","distinguishedName") -Filter *  | ForEach-Object -Process ({ if($_.distinguishedName -like "*$OULocaction*"){$null = $domainComputers.add($_.Name)}})
    return $domainComputers;
}

function processComputers
{
    param
    (
        $listOfComputers,
        $logPath
    )
    $mapOfComputersToDatedRecords = [ordered] @{};
    $listOfComputers | ForEach-Object -Process ({
        $computerName = $_;
        $computerLogs = getEventsForComputerLog -domainComputer $computerName;
        if($computerLogs -ne $null)
        {
            $userRecords = generateUserRecords -computerName $computerName -eventLogs $computerLogs -logPath $logPath;
            $null = $mapOfComputersToDatedRecords.add($computerName, $userRecords);
        }
        Write-Output "Finished $_" >> $logPath
    })
    return $mapOfComputersToDatedRecords;
}

function getEventsForComputerLog
{
    param
    (
        $domainComputer
    )
    if(Test-Connection $domainComputer -Quiet -Count 1)
    {
        $startTime = $((Get-Date).AddDays(-2).ToUniversalTime().GetDateTimeFormats()[102]);
        $endTime = $((Get-Date).ToUniversalTime().GetDateTimeFormats()[102]);

        [xml]$xmlFilter = "<QueryList>
            <Query Id=`"0`" Path=`"Security`">
                <Select Path=`"Security`">*[System[(EventID=4800 or EventID=4801 or EventID=4648 or EventID=4647) and TimeCreated[@SystemTime&gt;='$startTime' and @SystemTime&lt;='$endTime']]]</Select>
            </Query>
        </QueryList>"

        [System.Collections.ArrayList] $LogonAndOff = @();
        write-host "Getting events for $domainComputer";
        $LogonAndOffEvents = Get-WinEvent -ComputerName $domainComputer -FilterXml $xmlFilter;
        return $LogonAndOffEvents;
    }
    return $null;
}

function processComputersWithForwardEvents
{
    param
    (
        $listOfComputers,
        $daysOfLogs,
        $logPath
    )
    $MapOfComputersToLogs = [ordered] @{};
    $MapOfComputersToLogs = getEventsForForwardedEvents -days $daysOfLogs;
    $mapOfComputersToDatedRecords = [ordered] @{};
    $listOfComputers | ForEach-Object -Process ({
        $computerName = $_;
        $computerLogs = @();
        try
        {
            $computerLogs = $MapOfComputersToLogs[$computerName];
        }catch
        {
            write-host "$computerName has no records"
            return;
        }
        
        if($computerLogs -ne $null)
        {
            $userRecords = generateUserRecords -computerName $computerName -eventLogs $computerLogs -logPath $logPath;
            $null = $mapOfComputersToDatedRecords.add($computerName, $userRecords);
        }
        write-host "Finished $_"
    })
    return $mapOfComputersToDatedRecords;

}

function getEventsForForwardedEvents
{
    param
    (
        $days = 7
    )
    
    $endTime = 1000*3600*24*$days;
    $xpathFilter = "*[System[(EventID=4800 or EventID=4801 or EventID=4648 or EventID=4647) and TimeCreated[timediff(@SystemTime) <= $endTime]]]";

    [System.Collections.ArrayList] $LogonAndOff = @();
    $LogonAndOffEvents = Get-WinEvent -LogName 'ForwardedEvents' -FilterXPath $xpathFilter;
    return generatePcToEventsMap -events $LogonAndOffEvents;
}

function generatePcToEventsMap
{
    param(
        $events
    )
    $PCToEventMap = [ordered] @{};
    $events | ForEach-Object -Process ({
        $event = $_;
        $key = $($_.MachineName.split('.'))[0];
        appendToListOfMap -map $PCToEventMap -key $key -value $_;
    })

    return $PCToEventMap;
}

function generateUserRecords
{
    param(
        $computerName,
        $eventLogs,
        $logPath
    )
    $daysToSkip = @('Saturday','Sunday');
    $currentDate = $null;
    $dateMapToRecords = [ordered]@{};
    $dateMapToUserRecords = [ordered]@{};

    $eventLogs | ForEach-Object -Process ({

        if($_.TimeCreated.DayOfWeek -eq 'Saturday' -or $_.TimeCreated.DayOfWeek -eq 'Sunday')
        {
            return;
        }
        $rowTimeFormated = getDateFormatted -dateToFormat $_.TimeCreated
        appendToListOfMap -map $dateMapToRecords -key $rowTimeFormated -value $_
    })

    $dateMapToRecords.keys | ForEach-Object -Process ({
        $listOfEventsForDay = $dateMapToRecords[$_];
        $userRecordForDate = getStartAndEndTime -computerName $computerName -events $listOfEventsForDay -date $_ -logPath $logPath
        $null = $dateMapToUserRecords.add($_, $userRecordForDate);
    })

    return $dateMapToUserRecords;
}

function getDateFormatted
{
    param
    (
        [System.DateTime]$dateToFormat
    )
    return "$($dateToFormat.year)-$($([string]$dateToFormat.month).PadLeft(2,'0'))-$($([string]$dateToFormat.day).PadLeft(2,'0'))"
}

function getStartAndEndTime
{
    param
    (
        [string]$computerName,
        [System.Collections.ArrayList]$events,
        $date,
        $logPath
    )
    $userNamesToEvents = [ordered]@{};
    $userNamesToRecord = [ordered]@{};

    $events | ForEach-Object -Process ({
        $logEvent = $_;
        $nameAndLog = getLoginLogOffEventFromUser -logEvent $logEvent -computerName $computerName;
        if($nameAndLog -ne $null)
        {
            appendToListOfMap -map $userNamesToEvents -key $nameAndLog.user -value $nameAndLog.event;
        }
        
    })

    $userNamesToEvents.Keys | ForEach-Object -Process ({
        $userName = $_;
        $record = getStartAndEndTimeForAGivenUser -computer $computerName -userName $userName -events $userNamesToEvents[$userName] -date $date -logPath $logPath
        if($record -ne $null)
        {
            $userNamesToRecord.add($userName, $record);
        }
    })
    return $userNamesToRecord;

}

function getLoginLogOffEventFromUser
{
    param(
        $logEvent,
        [string]$computerName
        )

    if($logEvent.Id -eq 4648 -or $logEvent.Id -eq 4647 -or $logEvent.Id -eq 4801 -or $logEvent.Id -eq 4800)
        {
            $userName = IF ($logEvent.Id -eq 4648) {$logEvent.properties[5].Value} Else {$logEvent.properties[1].Value};

            if($userName -ne "$computerName`$" -and -not ($userName -like "UMFD*") -and -not ($userName -like "DWM*"))
            {
                return @{'user'=$userName; 'event'=$logEvent};
            }
        }
        return $null;
}

function getStartAndEndTimeForAGivenUser
{
    param
    (
        [string]$computer,
        [string]$userName,
        [System.Collections.ArrayList]$events,
        $date,
        $logPath
    )
     
    $eventCount = $events.count;
    $index = $eventCount - 1;
    $foundStartTime = $null;

    while($foundStartTime -eq $null -and $index -ge 0)
    {
        $logEvent = $events[$index];

        if($logEvent.Id -eq 4648 -or $logEvent.Id -eq 4801)
        {
            $foundStartTime = $logEvent.TimeCreated;
        }
        $index--;
    }

    $index = 0;
    $foundEndTime = $null;
    while($foundEndTime -eq $null -and $index -lt $eventCount)
    {
        $logEvent = $events[$index];

        if($logEvent.Id -eq 4800 -or $logEvent.Id -eq 4647)
        {
            $foundEndTime = $logEvent.TimeCreated;

            if($logEvent.Properties[1].Value -ne $userName)
            {
                Write-Host "Username mismatch expected $userName got $($logEvent.Properties[1].value)"
            }
        }
        $index++;
    }

    if($foundStartTime -eq $null -or $foundEndTime -eq $null -or $foundStartTime -gt $foundEndTime)
    {
        write-output "$computer startime beyond endtime or start/endtime null => startTime = $foundStartTime : endtime = $foundEndTime : computerName = $computerName : date = $date" >> $logPath
        return $null
    }
    write-output "$computer startTime = $foundStartTime endtime = $foundEndTime" >> $logPath;
    $startTime = $foundStartTime.ToUniversalTime();
    $endTime = $foundEndTime.ToUniversalTime();
    return [UserRecord]::New($userName, $computer, $startTime, $endTime, $date);    
}



function generateSFRecords
{
    param(
        $records,
        $json=$false
    )

    if($json -eq $true)
    {
        return generateSFRecordsAsJson -records $records;
    }else
    {
        return generateSFRecordsAsCSV -records $records;
    }
}

function generateSFRecordsAsJson
{
    param(
        $records
    )
    $jsonGenerator = [SFRecordGenerator]::New($true);
    return generateSFRecordWithGenerator -records $records -recordGenerator $jsonGenerator;
}

function generateSFRecordsAsCSV
{
    param(
        $records
    )
    $csvGenerator = [SFRecordGenerator]::New($false);
    return generateSFRecordWithGenerator -records $records -recordGenerator $csvGenerator;
}

function generateSFRecordWithGenerator
{
    param(
        $records,
        [SFRecordGenerator]$recordGenerator
    )

    $records.Keys | ForEach-Object -Process ({
        $ComputerName = $_;
        $datedRecords = $records[$ComputerName];

        $datedRecords.Keys | ForEach-Object -Process ({
            $date = $_;
            $userRecords = $datedRecords[$date];

            $userRecords.Keys | ForEach-Object -Process ({
                $user = $_;
                $userRecordFromDate = $($userRecords[$user]);
                $recordGenerator.GenerateRecord($userRecordFromDate);
            })
            
        })
    })
    return $recordGenerator.getRecordsList();
}

function querySFRecords
{
    param(
        $daysOfRecords
    )
    $queriedSFRecordsRaw = sfdx force:data:soql:query -q "SELECT Id, Name, Record_Date__c, User_Name__c, Computer__c, Last_Logout__c, First_Logon__c, Hours__c FROM ComputerLog__c WHERE Record_Date__c=Last_N_Days:5" -u dcurtin@midlandira.com.dcurtin -rcsv;
    $queriedSFRecordsAsCSV = $queriedSFRecordsRaw | ConvertFrom-Csv;
    return $queriedSFRecordsAsCSV;
}

function removeLesserHours
{
    param(
        $oldRecords,
        $newRecords
    )
    $mapOfNameToOldRecords = [ordered] @{};
    $oldRecords | ForEach-Object -Process ({ $mapOfNameToOldRecords.add($_.Name, $_)});

    $mapOfNameToNewRecords = [ordered] @{};
    $newRecords | ForEach-Object -Process ({ $mapOfNameToNewRecords.add($_.Name, $_)});

    $mapOfNameToOldRecords.Keys | ForEach-Object -Process ({
        $recordName = $_;
        if($mapOfNameToNewRecords[$recordName] -ne $null -and $mapOfNameToNewRecords[$recordName].Hours__c -lt $mapOfNameToOldRecords[$recordName].Hours__c)
        {
            $mapOfNameToNewRecords.remove($recordName);
        }
    })
    
    return $mapOfNameToNewRecords.Values;

}

function appendToListOfMap
{
    param($map,
            $key,
            $value
        )

            if($map.contains($key))
            {
                $null = $map[$key].add($value);
            }else
            {
                $null = $map.add($key, [System.Collections.ArrayList] @($value));
            }
}

class SFRecordGenerator
{
    $recordCount;
    $generateJson;
    [System.Collections.ArrayList]$generatedRecordList;

    SFRecordGenerator($generateJson)
    {
        $this.recordCount = 0;
        $this.generatedRecordList = @();
        $this.generateJson = $generateJson;
    }

    GenerateRecord($record)
    {
        if($this.generateJson)
        {
            $this.GenerateJson($record);
        }else
        {
            $this.GenerateCSV($record);
        }
    }

    GenerateJson($record)
    {
        $null = $this.generatedRecordList.Add($record.toJsonStructure($this.recordCount++));
    }

    GenerateCSV($record)
    {
        $null = $this.generatedRecordList.Add($record.toCSVStructure());
    }

    [System.Collections.ArrayList]getRecordsList()
    {
        return $this.generatedRecordList;
    }
}



class UserRecord
{
    [string]$userName;
    [string]$computer;
    [System.DateTime]$startDate;
    [System.DateTime]$endDate;
    [string]$date;
    [float]$hours;

    userRecord($userName, $computer, $startDate, $endDate, $date)
    {
        $this.userName = $userName;
        $this.computer = $computer;
        $this.startDate = $startDate;
        $this.endDate = $endDate; 
        $this.date = $date;

        $this.hours = ($this.endDate - $this.startDate).TotalHours;
    }

    [string]toString()
    {
        return '$this.userName $this.startDate $this.endDate $this.hours';
    }

    [System.Collections.Hashtable]toJsonStructure([string] $refId)
    {
        $endDateForm = "$($this.endDate.Year)-$(([string]$this.endDate.Month).PadLeft(2,'0'))-$(([string]$this.endDate.Day).PadLeft(2,'0'))T$(([string]$this.endDate.Hour).PadLeft(2,'0')):$(([string]$this.endDate.Minute).PadLeft(2,'0')):$(([string]$this.endDate.Second).PadLeft(2,'0'))";
        $startDateForm = "$($this.startDate.Year)-$(([string]$this.startDate.Month).PadLeft(2,'0'))-$(([string]$this.startDate.Day).PadLeft(2,'0'))T$(([string]$this.startDate.Hour).PadLeft(2,'0')):$(([string]$this.startDate.Minute).PadLeft(2,'0')):$(([string]$this.startDate.Second).PadLeft(2,'0'))";
        $attributes = [ordered]@{type="computerLog__c"; referenceId="computerLog__cRef$refId"};
        $recordDetails = [ordered]@{attributes=$attributes; Name="$($this.userName)-$($this.date)"; User_Name__c=$this.userName; Computer__c=$this.computer; Last_Logout__c=$endDateForm; First_Logon__c=$startDateForm; Hours__c=$this.hours; Record_Date__c=$this.date};

        return $recordDetails;
    }

    [string]toJson()
    {
        return $($this.toJsonStructure()|ConvertTo-Json);
    }

    [psobject]toCSVStructure()
    {
        $endDateForm = "$($this.endDate.Year)-$(([string]$this.endDate.Month).PadLeft(2,'0'))-$(([string]$this.endDate.Day).PadLeft(2,'0'))T$(([string]$this.endDate.Hour).PadLeft(2,'0')):$(([string]$this.endDate.Minute).PadLeft(2,'0')):$(([string]$this.endDate.Second).PadLeft(2,'0'))";
        $startDateForm = "$($this.startDate.Year)-$(([string]$this.startDate.Month).PadLeft(2,'0'))-$(([string]$this.startDate.Day).PadLeft(2,'0'))T$(([string]$this.startDate.Hour).PadLeft(2,'0')):$(([string]$this.startDate.Minute).PadLeft(2,'0')):$(([string]$this.startDate.Second).PadLeft(2,'0'))";
        
        [psobject]$record = New-Object psobject -Property $([ordered] @{Name="$($this.userName)-$($this.date)"; User_Name__c=$this.userName; Computer__c=$this.computer; Last_Logout__c=$endDateForm; First_Logon__c=$startDateForm; Hours__c=$this.hours; Record_Date__c=$this.date});
        return $record;
    }

}

main
