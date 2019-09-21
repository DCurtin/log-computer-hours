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
        $startTime = (Get-Date).AddDays(-4);
        $endTime = (Get-Date).AddDays(-1);
        $LogonAndOffEvents = Get-WinEvent -ComputerName $domainComputer -FilterHashtable @{LogName='Security'; Id=@('4800','4801','4648'); StartTime=$startTime; EndTime=$endTime}
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
    Get-ADComputer -Properties @("Name","distinguishedName") -Filter *  | ForEach-Object -Process ({ if($_.distinguishedName -like "*Computer*$OULocaction*"){$null = $domainComputers.add($_.Name)}})
    return $domainComputers;
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
        if($dateMapToRecords.contains($rowTimeFormated))
        {
            $null = $dateMapToRecords[$rowTimeFormated].add($_);
        }else
        {
            $null = $dateMapToRecords.add($rowTimeFormated, [System.Collections.ArrayList]@($_));
        }
        
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
    
    [string]$userName = $null;
    
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
            $userName = IF ($logEvent.Id -eq 4648) {$logEvent.properties[5].Value} Else {$logEvent.properties[1].Value} 
            $foundStartTime = IF ($userName -eq "$computerName`$" -or $userName -like "UMFD*" -or $userName -like "DWM*" ) {$null} Else {$logEvent.TimeCreated}
        }
        $index--;
    }

    $index = 0;
    $foundEndTime = $null
    while($foundEndTime -eq $null -and $index -lt $eventCount)
    {
        #Write-Host "End date $index"
        $logEvent = $events[$index];

        if($logEvent.Id -eq 4800)
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
    return New-Object userRecord($userName, $foundStartTime, $foundEndTime, $date);    
}

class userRecord
{
    [string]$userName
    [System.DateTime]$startDate
    [System.DateTime]$endDate
    [string]$date
    [float]$hours

    userRecord($userName, $startDate, $endDate, $date)
    {
        $this.userName = $userName;
        $this.startDate = $startDate;
        $this.endDate = $endDate; 
        $this.date = $date;

        $this.hours = ($this.endDate - $this.startDate).TotalHours;
    }

    [string]toString()
    {
        return '$this.userName $this.startDate $this.endDate $this.hours'
    }

}


$adComputers = getADComputers -OULocaction "Fort Myers"
$processedMap = processComputers -listOfComputers $adComputers

#$mapOfComputersToLog = generateMapOfComputersToLogEvents -domainComputers $adComputers

