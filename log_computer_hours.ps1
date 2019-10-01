#[System.Collections.ArrayList] $LogonAndOff = @();
#Get-EventLog -ComputerName curtin-mobile Security | ForEach-Object -Process ({ if($_.EventId -eq 4800 -or $_.EventId -eq 4801 -or ($_.EventId -eq 4624 -and $_.Message.contains('dcurtin'))){ $daltonSecLogonAndOff.Add($_)} })

function processComputers
{
    param
    (
        $listOfComputers
    )
    $mapOfComputersToDatedRecords = [ordered] @{};
    $listOfComputers | ForEach-Object -Process ({
        $computerName = $_;
        $computerLogs = getEventsForComputerLog -domainComputer $computerName;
        if($computerLogs -ne $null)
        {
            $userRecords = generateUserRecords -computerName $computerName -eventLogs $computerLogs;
            $null = $mapOfComputersToDatedRecords.add($computerName, $userRecords);
        }
        write-host "Finished $_"
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
        [System.Collections.ArrayList] $LogonAndOff = @();
        $startTime = (Get-Date).AddDays(-7);
        $endTime = (Get-Date);
        $LogonAndOffEvents = Get-WinEvent -ComputerName $domainComputer -FilterHashtable @{LogName='Security'; Id=@('4800','4801','4648','4647'); StartTime=$startTime; EndTime=$endTime}
        return $LogonAndOffEvents;
    }
    return $null;
}

function getADComputers
{
    param
    (
        [string]$OULocaction
    )

    [System.Collections.ArrayList] $domainComputers = @();
    Get-ADComputer -Properties @("Name","distinguishedName") -Filter *  | ForEach-Object -Process ({ if($_.distinguishedName -like "*$OULocaction*"){$null = $domainComputers.add($_.Name)}})
    #$userIndex = $domainComputers.IndexOf('WHETSELL');
    #$user = $domainComputers[$userIndex];
    return $domainComputers
    #return @($user)
}

function generateUserRecords
{
    param
    (
        $computerName,
        $eventLogs
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
        #Write-Host $_
        #if($currentDate -ne $rowTimeFormated)
        #{
        #    $currentDate = $rowTimeFormated;
        #    $dateMapToRecords.add($currentDate, $_);
        #}
        #$rowTimeFormated.add($rowTimeFormated, $_);
        appendToListOfMap -map $dateMapToRecords -key $rowTimeFormated -value $_
        
    })

    $dateMapToRecords.keys | ForEach-Object -Process ({
        $listOfEventsForDay = $dateMapToRecords[$_];
        $userRecordForDate = getStartAndEndTime -computerName $computerName -events $listOfEventsForDay -date $_
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
        $date
    )
    $userNamesToEvents = [ordered]@{};
    $userNamesToRecord = [ordered]@{};

    $events | ForEach-Object -Process ({
        $logEvent = $_;
        $nameAndLog = getLoginLogOffEventFromUser -logEvent $logEvent -computerName $computerName
        if($nameAndLog -ne $null)
        {
            appendToListOfMap -map $userNamesToEvents -key $nameAndLog.user -value $nameAndLog.event
        }
        
    })

    $userNamesToEvents.Keys | ForEach-Object -Process ({
        $userName = $_;
        $record = getStartAndEndTimeForAGivenUser -computer $computerName -userName $userName -events $userNamesToEvents[$userName] -date $date
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
            $userName = IF ($logEvent.Id -eq 4648) {$logEvent.properties[5].Value} Else {$logEvent.properties[1].Value}

            if($userName -ne "$computerName`$" -and -not ($userName -like "UMFD*") -and -not ($userName -like "DWM*"))
            {
                #Write-Host $userName $logEvent.Id
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
        $date
    )
     
    $eventCount = $events.count;
    $index = $eventCount - 1;
    #write-host $eventCount
    $foundStartTime = $null;

    while($foundStartTime -eq $null -and $index -ge 0)
    {
        #Write-Host "event id: $($events[$index].Id)"
        #Write-Host "Start date $index"
        $logEvent = $events[$index];

        if($logEvent.Id -eq 4648 -or $logEvent.Id -eq 4801)
        {
            $foundStartTime = $logEvent.TimeCreated
        }
        $index--;
    }

    $index = 0;
    $foundEndTime = $null
    while($foundEndTime -eq $null -and $index -lt $eventCount)
    {
        #Write-Host "End date $index"
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

    if($foundStartTime -eq $null -or $foundEndTime -eq $null)
    {
        write-host "startTime = $foundStartTime : endtime = $foundEndTime : computerName = $computerName : date = $date"
        return $null
    }
    write-host "startTime = $foundStartTime endtime = $foundEndTime"
    $startTime = $foundStartTime.ToUniversalTime();
    $endTime = $foundEndTime.ToUniversalTime();
    return [UserRecord]::New($userName, $computer, $startTime, $endTime, $date);    
}

function appendToListOfMap
{
    param($map,
            $key,
            $value
        )

            if($map.contains($key))
            {
                $null = $map[$key].add($value)
            }else
            {
                $null = $map.add($key, [System.Collections.ArrayList] @($value));
            }
}

function generateSFRecords
{
    param(
        $records,
        $json=$false
    )

    if($json -eq $true)
    {
        return generateSFRecordsAsJson -records $records
    }else
    {
        return generateSFRecordsAsCSV -records $records
    }
}

function generateSFRecordsAsJson
{
    param(
        $records
    )
    $jsonGenerator = [SFRecordGenerator]::New($true);
    return generateSFRecordWithGenerator -records $records -recordGenerator $jsonGenerator
}

function generateSFRecordsAsCSV
{
    param(
        $records
    )
    $csvGenerator = [SFRecordGenerator]::New($false);
    return generateSFRecordWithGenerator -records $records -recordGenerator $csvGenerator
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
            $userRecords = $datedRecords[$date]

            $userRecords.Keys | ForEach-Object -Process ({
                $user = $_;
                #Write-Host "$user $($userRecords[$user].userName)"
                $userRecordFromDate = $($userRecords[$user])
                #Write-Host $userRecordFromDate.userName;
                #[userRecord]$userRecordForCurrentDate = $($userRecord[0]);
                $recordGenerator.GenerateRecord($userRecordFromDate)
            })
            
        })
    })
    return $recordGenerator.getRecordsList();
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
    
    return $mapOfNameToNewRecords.Values

}

class SFRecordGenerator
{
    $recordCount
    $generateJson
    [System.Collections.ArrayList]$generatedRecordList

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
    [string]$userName
    [string]$computer
    [System.DateTime]$startDate
    [System.DateTime]$endDate
    [string]$date
    [float]$hours

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
        return '$this.userName $this.startDate $this.endDate $this.hours'
    }

    [System.Collections.Hashtable]toJsonStructure([string] $refId)
    {
        $endDateForm = "$($this.endDate.Year)-$(([string]$this.endDate.Month).PadLeft(2,'0'))-$(([string]$this.endDate.Day).PadLeft(2,'0'))T$(([string]$this.endDate.Hour).PadLeft(2,'0')):$(([string]$this.endDate.Minute).PadLeft(2,'0')):$(([string]$this.endDate.Second).PadLeft(2,'0'))"
        $startDateForm = "$($this.startDate.Year)-$(([string]$this.startDate.Month).PadLeft(2,'0'))-$(([string]$this.startDate.Day).PadLeft(2,'0'))T$(([string]$this.startDate.Hour).PadLeft(2,'0')):$(([string]$this.startDate.Minute).PadLeft(2,'0')):$(([string]$this.startDate.Second).PadLeft(2,'0'))"
        $attributes = [ordered]@{type="computerLog__c"; referenceId="computerLog__cRef$refId"};
        $recordDetails = [ordered]@{attributes=$attributes; Name="$($this.userName)-$($this.date)"; User_Name__c=$this.userName; Computer__c=$this.computer; Last_Logout__c=$endDateForm; First_Logon__c=$startDateForm; Hours__c=$this.hours; Record_Date__c=$this.date}

        return $recordDetails;
    }

    [string]toJson()
    {
        return $($this.toJsonStructure()|ConvertTo-Json);
    }

    [psobject]toCSVStructure()
    {
        $endDateForm = "$($this.endDate.Year)-$(([string]$this.endDate.Month).PadLeft(2,'0'))-$(([string]$this.endDate.Day).PadLeft(2,'0'))T$(([string]$this.endDate.Hour).PadLeft(2,'0')):$(([string]$this.endDate.Minute).PadLeft(2,'0')):$(([string]$this.endDate.Second).PadLeft(2,'0'))"
        $startDateForm = "$($this.startDate.Year)-$(([string]$this.startDate.Month).PadLeft(2,'0'))-$(([string]$this.startDate.Day).PadLeft(2,'0'))T$(([string]$this.startDate.Hour).PadLeft(2,'0')):$(([string]$this.startDate.Minute).PadLeft(2,'0')):$(([string]$this.startDate.Second).PadLeft(2,'0'))"        
        
        [psobject]$record = New-Object psobject -Property $([ordered] @{Name="$($this.userName)-$($this.date)"; User_Name__c=$this.userName; Computer__c=$this.computer; Last_Logout__c=$endDateForm; First_Logon__c=$startDateForm; Hours__c=$this.hours; Record_Date__c=$this.date})
        return $record;
    }

}

[System.Collections.ArrayList]$adComputersFL = getADComputers -OULocaction "Fort Myers";
[System.Collections.ArrayList]$adComputersSD = getADComputers -OULocaction "External-Shared";
[System.Collections.ArrayList]$adComputersIL = getADComputers -OULocaction "Chicago";
[System.Collections.ArrayList]$adComputerAdmin = getADComputers -OULocaction "Administrators";

[System.Collections.ArrayList]$combinedComputers = $();

$combinedComputers.AddRange($adComputersFL);
$combinedComputers.AddRange($adComputersSD);
$combinedComputers.AddRange($adComputersIL);
$combinedComputers.AddRange($adComputerAdmin);

#$processedMap = [ordered]@{WHETSELL=$([ordered]@{"2019-09-26"=$([ordered]@{bwhetsell=$([UserRecord]::new('testName','testComputer',$(Get-Date),$(Get-Date),'2019-09-26'))})})}
$processedMap = processComputers -listOfComputers $adComputers

$newRecords = $(generateSFRecords -records $processedMap -json $false)

$oldRecordsRaw = sfdx force:data:soql:query -q "SELECT Id, Name, Record_Date__c, User_Name__c, Computer__c, Last_Logout__c, First_Logon__c, Hours__c FROM ComputerLog__c WHERE Record_Date__c=Last_N_Days:7" -u dcurtin@midlandira.com.dcurtin -rcsv
$oldRecords = $oldRecordsRaw | ConvertFrom-Csv

$prunedRecords = $(removeLesserHours -oldRecords $oldRecords -newRecords $newRecords) | ConvertTo-Csv -NoTypeInformation

[IO.File]::WriteAllLines('C:\users\dcurtin\ComputerLogs__c.csv', $prunedRecords)
sfdx force:data:bulk:upsert -s computerlog__c -f 'C:\users\dcurtin\ComputerLogs__c.csv' -i Name -u dcurtin@midlandira.com.dcurtin
