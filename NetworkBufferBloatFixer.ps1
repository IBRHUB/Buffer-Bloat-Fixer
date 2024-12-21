#Requires -RunAsAdministrator
<#
.SYNOPSIS
  IBRPRIDE.COM - Network Buffer Bloat Fixer (Improved v3)
.DESCRIPTION
  Applies (Enable) or Reverts (Disable) registry/network tweaks to reduce buffer bloat.
.NOTES
  Version: 3.0
  Author:  IBRHUB
  Date:    2024-xx-xx
  Disclaimer: Use at your own risk. May affect your network/system settings.
#>

# -----------------------------------------------------------
# Check if the script is running with Administrator privileges
# -----------------------------------------------------------
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f `
        $MyInvocation.MyCommand.Definition) -Verb RunAs
    exit
}

# -----------------------------------------------------------
# Function: Show-Banner (Colorful banner at script start)
# -----------------------------------------------------------
function Show-Banner {
    param (
        [string]$Title = "IBRPRIDE.COM - Network Buffer Bloat Fixer",
        [string]$Version = "v3.0"
    )
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Magenta
    Write-Host "  $Title  ($Version)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Magenta
    Write-Host ""
}

# -----------------------------------------------------------
# Function: Set-ConsoleBackground
# -----------------------------------------------------------
function Set-ConsoleBackground {
    $Host.UI.RawUI.WindowTitle = "QoS Network Buffer Bloat Fixer | @IBRHUB v3.0"
    $Host.UI.RawUI.BackgroundColor = "Black"
    $Host.PrivateData.ProgressBackgroundColor = "Black"
    $Host.PrivateData.ProgressForegroundColor = "White"
    # Adjust console window size as needed
    $Host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size(65, 28)
}

# -----------------------------------------------------------
# Menu Function: Write-Menu
# -----------------------------------------------------------
function Write-Menu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('InputObject')]
        $Entries,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('Name')]
        [string]
        $Title,

        [Parameter()]
        [switch]
        $Sort,

        [Parameter()]
        [switch]
        $MultiSelect
    )

    $script:cfgPrefix  = ' '
    $script:cfgPadding = 2
    $script:cfgSuffix  = ' '
    $script:cfgNested  = ' >'
    $script:cfgWidth   = 30

    [System.Console]::CursorVisible = $false
    $script:colorForeground = [System.Console]::ForegroundColor
    $script:colorBackground = [System.Console]::BackgroundColor

    function Set-Color ([switch]$Inverted) {
        switch ($Inverted) {
            $true {
                [System.Console]::ForegroundColor = $colorBackground
                [System.Console]::BackgroundColor = $colorForeground
            }
            Default {
                [System.Console]::ForegroundColor = $colorForeground
                [System.Console]::BackgroundColor = $colorBackground
            }
        }
    }

    function Get-Menu ($script:inputEntries) {
        Clear-Host
        Show-Banner -Title "IBRPRIDE.COM - Network Buffer Bloat Fixer" -Version "v3.0"

        if ($Title -ne $null) {
            $script:menuTitle = "$Title"
        } else {
            $script:menuTitle = 'Menu'
        }

        # Adjust how many items can be displayed per page
        $script:pageSize = ($host.UI.RawUI.WindowSize.Height - 5)

        $script:menuEntries = @()

        switch ($inputEntries.GetType().Name) {
            'String' {
                $script:menuEntryTotal = 1
                $script:menuEntries = New-Object PSObject -Property @{
                    Command   = ''
                    Name      = $inputEntries
                    Selected  = $false
                    onConfirm = 'Name'
                }
                break
            }
            'Object[]' {
                $script:menuEntryTotal = $inputEntries.Length
                foreach ($i in 0..($menuEntryTotal - 1)) {
                    $script:menuEntries += New-Object PSObject -Property @{
                        Command   = ''
                        Name      = $($inputEntries)[$i]
                        Selected  = $false
                        onConfirm = 'Name'
                    }
                    $i++
                }
                break
            }
            'Hashtable' {
                $script:menuEntryTotal = $inputEntries.Count
                foreach ($i in 0..($menuEntryTotal - 1)) {
                    if ($menuEntryTotal -eq 1) {
                        $tempName    = $($inputEntries.Keys)
                        $tempCommand = $($inputEntries.Values)
                    } else {
                        $tempName    = $($inputEntries.Keys)[$i]
                        $tempCommand = $($inputEntries.Values)[$i]
                    }

                    if ($tempCommand -is [System.Collections.Hashtable]) {
                        $tempAction = 'Hashtable'
                    }
                    elseif ($tempCommand -and $tempCommand.Length -ge 1 -and `
                        $tempCommand.Substring(0,1) -eq '@') {
                        $tempAction = 'Invoke'
                    }
                    else {
                        $tempAction = 'Command'
                    }

                    $script:menuEntries += New-Object PSObject -Property @{
                        Name      = $tempName
                        Command   = $tempCommand
                        Selected  = $false
                        onConfirm = $tempAction
                    }
                    $i++
                }
                break
            }
            Default {
                Write-Error "Type '$($inputEntries.GetType().Name)' not supported. Use Array or Hashtable."
                exit
            }
        }

        if ($Sort) {
            $script:menuEntries = $menuEntries | Sort-Object -Property Name
        }

        $script:entryWidth = ($menuEntries.Name | Measure-Object -Maximum -Property Length).Maximum
        if ($MultiSelect) {
            $script:entryWidth += 4
        }
        if ($entryWidth -lt $script:cfgWidth) {
            $script:entryWidth = $script:cfgWidth
        }
        $script:pageWidth   = $script:cfgPrefix.Length + $script:cfgPadding + `
                              $script:entryWidth + $script:cfgPadding + $script:cfgSuffix.Length
        $script:pageCurrent = 0
        $script:pageTotal   = [math]::Ceiling((($menuEntryTotal - $pageSize) / $pageSize))

        [System.Console]::WriteLine("")
        $script:lineTitle = [System.Console]::CursorTop
        # Title in a color
        Write-Host "  $menuTitle" -ForegroundColor Yellow
        [System.Console]::WriteLine("")
        $script:lineTop = [System.Console]::CursorTop
    }

    function Get-Page {
        if ($pageTotal -ne 0) {
            Update-Header
        }
        for ($i = 0; $i -le $pageSize; $i++) {
            [System.Console]::WriteLine("".PadRight($pageWidth) + ' ')
        }
        [System.Console]::CursorTop = $lineTop

        $script:pageEntryFirst = ($pageSize * $pageCurrent)
        if ($pageCurrent -eq $pageTotal) {
            $script:pageEntryTotal = ($menuEntryTotal - ($pageSize * $pageTotal))
        } else {
            $script:pageEntryTotal = $pageSize
        }
        $script:lineSelected = 0

        for ($i = 0; $i -le ($pageEntryTotal - 1); $i++) {
            Write-Entry $i
        }
    }

    function Write-Entry ([int16]$Index, [switch]$Update) {
        switch ($Update) {
            $true  { $lineHighlight = $false; break }
            Default { $lineHighlight = ($Index -eq $lineSelected) }
        }
        $pageEntry = $menuEntries[($pageEntryFirst + $Index)].Name

        if ($MultiSelect) {
            switch ($menuEntries[($pageEntryFirst + $Index)].Selected) {
                $true  { $pageEntry = "[X] $pageEntry" }
                Default { $pageEntry = "[ ] $pageEntry" }
            }
        }

        if ($menuEntries[($pageEntryFirst + $Index)].onConfirm -in 'Hashtable', 'Invoke') {
            $pageEntry = "$pageEntry".PadRight($entryWidth) + "$script:cfgNested"
        }
        else {
            $pageEntry = "$pageEntry".PadRight($entryWidth + $script:cfgNested.Length)
        }

        [System.Console]::Write("`r" + $script:cfgPrefix)
        if ($lineHighlight) {
            # Invert the colors for highlighting
            Set-Color -Inverted
        }
        [System.Console]::Write("".PadLeft($script:cfgPadding) + $pageEntry + "".PadRight($script:cfgPadding))
        if ($lineHighlight) {
            Set-Color
        }
        [System.Console]::Write($script:cfgSuffix + "`n")
    }

    function Update-Entry ([int16]$Index) {
        [System.Console]::CursorTop = ($lineTop + $lineSelected)
        Write-Entry $lineSelected -Update
        $script:lineSelected = $Index
        [System.Console]::CursorTop = ($lineTop + $Index)
        Write-Entry $lineSelected
        [System.Console]::CursorTop = $lineTop
    }

    function Update-Header {
        $pCurrent = ($pageCurrent + 1)
        $pTotal   = ($pageTotal + 1)
        $pOffset  = ($pTotal.ToString()).Length
        $script:pageNumber = "{0,-$pOffset}{1,0}" -f "$($pCurrent.ToString().PadLeft($pOffset))","/$pTotal"
        [System.Console]::CursorTop  = $lineTitle
        [System.Console]::CursorLeft = ($pageWidth - ($pOffset * 2) - 1)
        [System.Console]::WriteLine("$script:pageNumber")
    }

    # Initialize the menu
    Get-Menu $Entries
    Get-Page
    $menuNested = [ordered]@{}

    do {
        $inputLoop = $true
        [System.Console]::CursorTop = $lineTop
        [System.Console]::Write("`r")
        $menuInput = [System.Console]::ReadKey($false)
        $entrySelected = $menuEntries[($pageEntryFirst + $lineSelected)]

        switch ($menuInput.Key) {
            { $_ -in 'Escape','Backspace' } {
                if ($menuNested.Count -ne 0) {
                    $pageCurrent = 0
                    $Title = $($menuNested.GetEnumerator())[$menuNested.Count - 1].Name
                    Get-Menu $($menuNested.GetEnumerator())[$menuNested.Count - 1].Value
                    Get-Page
                    $menuNested.RemoveAt($menuNested.Count - 1) | Out-Null
                }
                else {
                    Clear-Host
                    $inputLoop = $false
                    [System.Console]::CursorVisible = $true
                    return $null
                }
                break
            }
            'DownArrow' {
                if ($lineSelected -lt ($pageEntryTotal - 1)) {
                    Update-Entry ($lineSelected + 1)
                }
                elseif ($pageCurrent -ne $pageTotal) {
                    $pageCurrent++
                    Get-Page
                }
                break
            }
            'UpArrow' {
                if ($lineSelected -gt 0) {
                    Update-Entry ($lineSelected - 1)
                }
                elseif ($pageCurrent -ne 0) {
                    $pageCurrent--
                    Get-Page
                    Update-Entry ($pageEntryTotal - 1)
                }
                break
            }
            'Home' {
                if ($lineSelected -ne 0) {
                    Update-Entry 0
                }
                elseif ($pageCurrent -ne 0) {
                    $pageCurrent--
                    Get-Page
                    Update-Entry ($pageEntryTotal - 1)
                }
                break
            }
            'End' {
                if ($lineSelected -ne ($pageEntryTotal - 1)) {
                    Update-Entry ($pageEntryTotal - 1)
                }
                elseif ($pageCurrent -ne $pageTotal) {
                    $pageCurrent++
                    Get-Page
                }
                break
            }
            { $_ -in 'RightArrow','PageDown' } {
                if ($pageCurrent -lt $pageTotal) {
                    $pageCurrent++
                    Get-Page
                }
                break
            }
            { $_ -in 'LeftArrow','PageUp' } {
                if ($pageCurrent -gt 0) {
                    $pageCurrent--
                    Get-Page
                }
                break
            }
            'Spacebar' {
                if ($MultiSelect) {
                    switch ($entrySelected.Selected) {
                        $true  { $entrySelected.Selected = $false }
                        $false { $entrySelected.Selected = $true }
                    }
                    Update-Entry ($lineSelected)
                }
                break
            }
            'Insert' {
                if ($MultiSelect) {
                    $menuEntries | ForEach-Object { $_.Selected = $true }
                    Get-Page
                }
                break
            }
            'Delete' {
                if ($MultiSelect) {
                    $menuEntries | ForEach-Object { $_.Selected = $false }
                    Get-Page
                }
                break
            }
            'Enter' {
                # Handle MultiSelect scenario
                if ($MultiSelect) {
                    Clear-Host
                    $menuEntries | ForEach-Object {
                        if (($_.Selected) -and ($_.Command -ne $null) -and `
                            ($entrySelected.Command.GetType().Name -ne 'Hashtable')) {
                            Invoke-Expression -Command $_.Command
                        }
                        elseif ($_.Selected) {
                            return $_.Name
                        }
                    }
                    $inputLoop = $false
                    [System.Console]::CursorVisible = $true
                    break
                }

                # Handle onConfirm
                switch ($entrySelected.onConfirm) {
                    'Hashtable' {
                        $menuNested.$Title = $inputEntries
                        $Title = $entrySelected.Name
                        Get-Menu $entrySelected.Command
                        Get-Page
                        break
                    }
                    'Invoke' {
                        $menuNested.$Title = $inputEntries
                        $Title = $entrySelected.Name
                        if ($entrySelected.Command -and $entrySelected.Command.Length -gt 1) {
                            Get-Menu (Invoke-Expression -Command $entrySelected.Command.Substring(1))
                            Get-Page
                        }
                        else {
                            Write-Host "Invalid or empty command for Invoke. Cannot proceed." -ForegroundColor Red
                        }
                        break
                    }
                    'Command' {
                        # --- Fix for empty/exit scenario ---
                        if ([string]::IsNullOrWhiteSpace($entrySelected.Command)) {
                            # It's empty -> just exit (or do nothing special)
                            Clear-Host
                            Write-Host "Exiting..." -ForegroundColor DarkCyan
                            $inputLoop = $false
                            [System.Console]::CursorVisible = $true
                        }
                        else {
                            Clear-Host
                            Invoke-Expression -Command $entrySelected.Command
                            $inputLoop = $false
                            [System.Console]::CursorVisible = $true
                        }
                        break
                    }
                    'Name' {
                        Clear-Host
                        return $entrySelected.Name
                        $inputLoop = $false
                        [System.Console]::CursorVisible = $true
                    }
                }
            }
        }
    } while ($inputLoop)
}

# -----------------------------------------------------------
# Function: FixUploadBufferBloat (Full Registry/Netsh Tweaks)
# -----------------------------------------------------------
function FixUploadBufferBloat {
  param (
    [switch]$Enable,
    [switch]$Disable
  )

  if ($Enable) {
    Write-Host "`n[ $(Get-Date -Format 'HH:mm:ss') ] Applying network settings to improve performance..." -ForegroundColor Yellow

    # Get all network adapters
    $NIC = @()
    foreach ($a in Get-NetAdapter -Physical | Select-Object DeviceID, Name) { 
      $NIC += @{ $($a.Name) = $($a.DeviceID) }
    }
    
    # ----------------------------
    # QoS settings
    # ----------------------------
    $enableQos = {    
      New-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' -ea 0 | Out-Null
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' 'Do not use NLA' 1 -type string -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DisableUserTOSSetting 0 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' NonBestEffortLimit 80 -type dword -force -ea 0 
      Get-NetQosPolicy | Remove-NetQosPolicy -Confirm:$False -ea 0
      Remove-NetQosPolicy 'Bufferbloat' -Confirm:$False -ea 0
      New-NetQosPolicy 'Bufferbloat' -Precedence 254 -DSCPAction 46 -NetworkProfile Public -Default -MinBandwidthWeightAction 25 | Out-Null
    }
    &$enableQos *>$null

    # ----------------------------
    # TCP tweaks
    # ----------------------------
    $tcpTweaks = {
      $NIC.Values | ForEach-Object {
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$_" TcpAckFrequency 2 -type dword -force -ea 0  
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$_" TcpNoDelay 1 -type dword -force -ea 0
      }
      if (Get-Item 'HKLM:\SOFTWARE\Microsoft\MSMQ' -ea 0) { 
        Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters' TCPNoDelay 1 -type dword -force -ea 0
      }
      Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' NetworkThrottlingIndex 0xffffffff -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' SystemResponsiveness 10 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' NonBestEffortLimit 80 -type dword -force -ea 0 
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' LargeSystemCache 0 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' Size 3 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DefaultTTL 64 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' MaxUserPort 65534 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' TcpTimedWaitDelay 30 -type dword -force -ea 0
      New-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' -ea 0 | Out-Null
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' 'Do not use NLA' 1 -type string -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' DnsPriority 6 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' HostsPriority 5 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' LocalPriority 4 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' NetbtPriority 7 -type dword -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DisableTaskOffload -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' MaximumReassemblyHeaders 0xffff -type dword -force -ea 0 
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters' FastSendDatagramThreshold 1500 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters' DefaultReceiveWindow (2048 * 4096) -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters' DefaultSendWindow (2048 * 4096) -type dword -force -ea 0
    }
    &$tcpTweaks *>$null

    # Disable each adapter, apply net adapter advanced property changes, then re-enable
    $NIC.Keys | ForEach-Object { Disable-NetAdapter -InterfaceAlias $_ -Confirm:$False }

    # ----------------------------
    # NIC advanced property tweaks
    # ----------------------------
    $netAdaptTweaks = {
      foreach ($key in $NIC.Keys) {
        $netProperty = Get-NetAdapterAdvancedProperty -Name $key -RegistryKeyword 'NetworkAddress' -ErrorAction SilentlyContinue
        if ($null -ne $netProperty.RegistryValue -and $netProperty.RegistryValue -ne ' ') {
          $mac = $netProperty.RegistryValue 
        }
        Get-NetAdapter -Name $key | Reset-NetAdapterAdvancedProperty -DisplayName '*'
        if ($null -ne $mac) { 
          Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword 'NetworkAddress' -RegistryValue $mac 
        }
        $rx = (Get-NetAdapterAdvancedProperty -Name $key -RegistryKeyword '*ReceiveBuffers').NumericParameterMaxValue  
        $tx = (Get-NetAdapterAdvancedProperty -Name $key -RegistryKeyword '*TransmitBuffers').NumericParameterMaxValue
        if ($null -ne $rx -and $null -ne $tx) {
          Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword '*ReceiveBuffers' -RegistryValue $rx
          Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword '*TransmitBuffers' -RegistryValue $tx
        }
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword '*InterruptModeration' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword 'ITR' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword '*RSS' -RegistryValue 1
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword '*NumRssQueues' -RegistryValue 2
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword '*PriorityVLANTag' -RegistryValue 1
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword '*FlowControl' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword '*JumboPacket' -RegistryValue 1514
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword '*HeaderDataSplit' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword 'TcpSegmentation' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword 'RxOptimizeThreshold' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword 'WaitAutoNegComplete' -RegistryValue 1
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword 'PowerSavingMode' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword '*SelectiveSuspend' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword 'EnableGreenEthernet' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword 'AdvancedEEE' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword 'EEE' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name $key -RegistryKeyword '*EEE' -RegistryValue 0
      }
    }
    &$netAdaptTweaks *>$null

    $netAdaptTweaks2 = { 
      $NIC.Keys | ForEach-Object {
        Set-NetAdapterRss -Name $_ -NumberOfReceiveQueues 2 -MaxProcessorNumber 4 -Profile 'NUMAStatic' -Enabled $true -ea 0
        Enable-NetAdapterQos -Name $_ -ea 0
        Enable-NetAdapterChecksumOffload -Name $_ -ea 0
        Disable-NetAdapterRsc -Name $_ -ea 0
        Disable-NetAdapterUso -Name $_ -ea 0
        Disable-NetAdapterLso -Name $_ -ea 0
        Disable-NetAdapterIPsecOffload -Name $_ -ea 0
        Disable-NetAdapterEncapsulatedPacketTaskOffload -Name $_ -ea 0
      }

      Set-NetOffloadGlobalSetting -TaskOffload Enabled
      Set-NetOffloadGlobalSetting -Chimney Disabled
      Set-NetOffloadGlobalSetting -PacketCoalescingFilter Disabled
      Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Disabled
      Set-NetOffloadGlobalSetting -ReceiveSideScaling Enabled
      Set-NetOffloadGlobalSetting -NetworkDirect Enabled
      Set-NetOffloadGlobalSetting -NetworkDirectAcrossIPSubnets Allowed -ea 0
    }
    &$netAdaptTweaks2 *>$null

    $NIC.Keys | ForEach-Object { Enable-NetAdapter -InterfaceAlias $_ -Confirm:$False }

    # ----------------------------
    # netsh tweaks
    # ----------------------------
    $netShTweaks = {
      netsh winsock set autotuning on
      netsh int udp set global uro=disabled
      netsh int tcp set heuristics wsh=disabled forcews=enabled
      netsh int tcp set supplemental internet minrto=300
      netsh int tcp set supplemental internet icw=10
      netsh int tcp set supplemental internet congestionprovider=newreno
      netsh int tcp set supplemental internet enablecwndrestart=disabled
      netsh int tcp set supplemental internet delayedacktimeout=40
      netsh int tcp set supplemental internet delayedackfrequency=2
      netsh int tcp set supplemental internet rack=enabled
      netsh int tcp set supplemental internet taillossprobe=enabled
      netsh int tcp set security mpp=disabled
      netsh int tcp set security profiles=disabled

      netsh int tcp set global rss=enabled
      netsh int tcp set global autotuninglevel=Normal
      netsh int tcp set global ecncapability=enabled
      netsh int tcp set global timestamps=enabled
      netsh int tcp set global initialrto=1000
      netsh int tcp set global rsc=disabled
      netsh int tcp set global nonsackrttresiliency=disabled
      netsh int tcp set global maxsynretransmissions=4
      netsh int tcp set global fastopen=enabled
      netsh int tcp set global fastopenfallback=enabled
      netsh int tcp set global hystart=enabled
      netsh int tcp set global prr=enabled
      netsh int tcp set global pacingprofile=off

      netsh int ip set global loopbacklargemtu=enable
      netsh int ip set global loopbackworkercount=4
      netsh int ip set global loopbackexecutionmode=inline
      netsh int ip set global reassemblylimit=267748640
      netsh int ip set global reassemblyoutoforderlimit=48
      netsh int ip set global sourceroutingbehavior=drop
      netsh int ip set dynamicport tcp start=32769 num=32766
      netsh int ip set dynamicport udp start=32769 num=32766
    }
    &$netShTweaks *>$null

    Write-Host "`nSettings applied successfully. A system restart may be required." -ForegroundColor Green
  }
  elseif ($Disable) {
    Write-Host "`n[ $(Get-Date -Format 'HH:mm:ss') ] Reverting settings to defaults..." -ForegroundColor Yellow

    $NIC = @()
    foreach ($a in Get-NetAdapter -Physical | Select-Object DeviceID, Name) { 
      $NIC += @{ $($a.Name) = $($a.DeviceID) }
    }

    # ----------------------------
    # Remove TCP tweaks
    # ----------------------------
    $revertTcpTweaks = {
      $NIC.Values | ForEach-Object {
        Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$_" TcpAckFrequency -force -ea 0
        Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$_" TcpDelAckTicks -force -ea 0
        Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$_" TcpNoDelay -force -ea 0
      }
      if (Get-Item 'HKLM:\SOFTWARE\Microsoft\MSMQ' -ea 0) { 
        Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters' TCPNoDelay -force -ea 0
      }
      Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' NetworkThrottlingIndex -force -ea 0
      Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' SystemResponsiveness -force -ea 0
      Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' NonBestEffortLimit -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' LargeSystemCache -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' Size -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DefaultTTL -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' MaxUserPort -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' TcpTimedWaitDelay -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' 'Do not use NLA' -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' DnsPriority -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' HostsPriority -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' LocalPriority -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' NetbtPriority -force -ea 0
    }
    &$revertTcpTweaks *>$null

    # ----------------------------
    # Reset registry tweaks
    # ----------------------------
    $resetRegtweaks = {
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters' FastSendDatagramThreshold -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters' DefaultSendWindow -force -ea 0 
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters' DefaultReceiveWindow -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' IRPStackSize -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DisableTaskOffload -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' MaximumReassemblyHeaders -force -ea 0  
    }
    &$resetRegtweaks *>$null

    # ----------------------------
    # Reset NIC adapter tweaks
    # ----------------------------
    $resetNetAdaptTweaks = {
      $NIC.Keys | ForEach-Object { Disable-NetAdapter -InterfaceAlias $_ -Confirm:$False }

      $NIC.Keys | ForEach-Object {
        $mac = (Get-NetAdapterAdvancedProperty -Name $_ -RegistryKeyword 'NetworkAddress' -ea 0).RegistryValue
        Get-NetAdapter -Name $_ | Reset-NetAdapterAdvancedProperty -DisplayName '*'
        if ($mac) {
          Set-NetAdapterAdvancedProperty -Name $_ -RegistryKeyword 'NetworkAddress' -RegistryValue $mac
        }
      }

      $NIC.Keys | ForEach-Object { Enable-NetAdapter -InterfaceAlias $_ -Confirm:$False }
    }
    &$resetNetAdaptTweaks *>$null

    # ----------------------------
    # Reset netsh tweaks
    # ----------------------------
    $resetNetshTweaks = {
      netsh int ip set dynamicport tcp start=49152 num=16384
      netsh int ip set dynamicport udp start=49152 num=16384
      netsh int ip set global reassemblyoutoforderlimit=32
      netsh int ip set global reassemblylimit=267748640
      netsh int ip set global loopbackexecutionmode=adaptive 
      netsh int ip set global sourceroutingbehavior=dontforward
      netsh int ip reset
      netsh int ipv6 reset 
      netsh int ipv4 reset 
      netsh int tcp reset 
      netsh int udp reset 
      netsh winsock reset
    }
    &$resetNetshTweaks *>$null

    # ----------------------------
    # Remove QoS policies
    # ----------------------------
    $resetQos = {
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' 'Do not use NLA' -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DefaultTOSValue -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DisableUserTOSSetting -force -ea 0
      Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS' 'Tcp Autotuning Level' -force -ea 0
      Get-NetQosPolicy | Remove-NetQosPolicy -Confirm:$False -ea 0
    }
    &$resetQos *>$null

    Write-Host "`nSettings reverted to default. A system restart may be required." -ForegroundColor Green
  }
}

# -----------------------------------------------------------
# Script Entry Point
# -----------------------------------------------------------
Set-ConsoleBackground
Clear-Host

# Show banner once (optional) before menu:
Show-Banner -Title "IBRPRIDE.COM - Network Buffer Bloat Fixer" -Version "v3.0"

# Main menu entries (Exit has empty string -> triggers "Command" case)
$menuEntries = @{
    'Enable Network Tweaks (Reduce Buffer Bloat)' = 'FixUploadBufferBloat -Enable'
    'Disable Tweaks and Revert to Defaults'       = 'FixUploadBufferBloat -Disable'
    'Exit'                                        = ''
}

# Display the menu
$result = Write-Menu -Title 'MAIN MENU' -Entries $menuEntries

if ([string]::IsNullOrEmpty($result)) {
    Write-Host "Exiting..." -ForegroundColor DarkRed
}
else {
    Write-Host "Executing command: $result" -ForegroundColor Cyan
}
