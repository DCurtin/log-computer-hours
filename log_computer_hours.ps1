#[System.Collections.ArrayList] $LogonAndOff = @();
#Get-EventLog -ComputerName curtin-mobile Security | ForEach-Object -Process ({ if($_.EventId -eq 4800 -or $_.EventId -eq 4801 -or ($_.EventId -eq 4624 -and $_.Message.contains('dcurtin'))){ $daltonSecLogonAndOff.Add($_)} })

function find

function generateMapOfComputersToLogEvents
{
    param
    (
        $domainComputers
    )

    $computerToLogMap = @{};
    $domainComputers | ForEach-Object -Process ({
        Write-Host $_
        if(Test-Connection $_ -Quiet -Count 1)
        {
            Write-host "$_ started"
            [System.Collections.ArrayList] $LogonAndOff = @();
            $LogonAndOff = Get-WinEvent -ComputerName $_ -FilterHashtable @{ LogName='Security'; Id=@('4800','4801','4684')}
            #$null = $computerToLogMap.add($_,$LogonAndOff);
            Write-host "$_ completed"


        }
    })
    return $domainComputers;
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

function getDateFormatted
{
    param
    (
        [System.DateTime]$dateToFormat
    )
    return "$($dateToFormat.year)-$($dateToFormat.month)-$($dateToFormat.day)"
}

function generateUserRecords
{
    param
    (
        $eventLogs
    )
    $currentDate = $null;
    [order]$dateMapToRecords = @{};

    $eventLogs | ForEach-Object -Process ({
        $rowTimeFormated = getDateFormatted -dateToFormat $_.TimeCreated
        #if($currentDate -eq $null -or ($currentDate -ne $rowTimeFormated))
        #{
        #    $currentDate = $rowTimeFormated;
        #    
        #}
        $rowTimeFormated.add($rowTimeFormated, $_);
    })

    
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
$mapOfComputersToLog = generateMapOfComputersToLogEvents -domainComputers $adComputers

