<#PSScriptInfo

.VERSION 1.0.2

.GUID a447d12a-8ab9-4365-898c-63c482d8c22a

.AUTHOR Richard Hicks

.COMPANYNAME Richard M. Hicks Consulting, Inc.

.COPYRIGHT Copyright (C) 2023 Richard M. Hicks Consulting, Inc. All Rights Reserved.

.TAGS AbsoluteSecureAccess

#>

<#

.SYNOPSIS
    Updates firewall rules for Absolute Secure Access and Insights for Networks infrastructure servers.

.PARAMETER ServerRole
    Use this parameter to define the installed server role. Valid values are SecureAccessServer, InsightsForNetworksServer, and BandwidthTestServer.

.EXAMPLE
    .\Update-AbsoluteSecureAccessFirewallRule.ps1 -ServerRole SecureAccessServer

    Updates the firewall rules for the SecureAccessServer role.

.EXAMPLE
    .\Update-AbsoluteSecureAccessFirewallRule.ps1 -ServerRole InsightsForNetworksServer

    Updates the firewall rules for the InsightsForNetworksServer role.

.EXAMPLE
    .\Update-AbsoluteSecureAccessFirewallRule.ps1 -ServerRole BandwidthTestServer

    Updates the firewall rules for the BandwidthTestServer role.

.DESCRIPTION
    The Absolute Secure Access and Insights for Networks installer will, by default, create firewall rules for the required infrastructure servers. However, these rules are not created in a firewall rule group and are not easily identifiable. This script will create a firewall rule group named "Absolute Secure Access" and add the required firewall rules to that group. This makes it easier to identify the required firewall rules and manage them as a group.

.LINK
    https://github.com/richardhicks/AbsoluteSecureAccess/blob/master/Update-AbsoluteSecureAccessFirewallRule.ps1

.LINK
    https://directaccess.richardhicks.com/absolute-secure-access/

.NOTES
    Version:        1.0.2
    Creation Date:  August 2, 2023
    Last Updated:   August 2, 2023
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

[CmdletBinding()]

Param(

    [Parameter(Mandatory)]
    [ValidateSet('SecureAccessServer', 'InsightsForNetworksServer', 'BandwidthTestServer')]
    [string]$ServerRole

)

# Determine if the server is domain-joined
$DomainJoined = (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain

If ($DomainJoined) {

    Write-Verbose "Server $env:computername is domain-joined."

}

# Clean up default Absolute Secure Access firewall rules
If ($ServerRole -eq 'SecureAccessServer') {

    Write-Verbose "Server role $ServerRole selected."
    $Rules = Get-NetFirewallRule | Where-Object DisplayName -Like 'Secure Access*' -ErrorAction SilentlyContinue

    If ($Null -eq $Rules) {

        Write-Warning 'No Absolute Secure Access firewall rules found. Ensure the selected server role is correct and that the server software is installed.'
        Return

    }

    ForEach ($Rule in $Rules) {

        Write-Verbose "Updating firewall rule $($Rule.DisplayName)..."
        $Rule.Group = 'Absolute Secure Access'

        # Restrict firewall rule to the Windows domain profile if the server is domain-joined
        If ($DomainJoined) {

            Write-Verbose "Restricting firewall rule $($Rule.DisplayName) to domain profile..."
            $Rule.Profile = 'Domain'

        }

        $Rule | Set-NetFirewallRule

    }

}

# Clean up default Absolute Secure Access Insights for Networks firewall rules
If ($ServerRole -eq 'InsightsForNetworksServer') {

    Write-Verbose "Server role $ServerRole selected."
    $Rules = Get-NetFirewallRule | Where-Object DisplayName -Like 'Mobile IQ*' -ErrorAction SilentlyContinue

    If ($Null -eq $Rules) {

        Write-Warning 'No Insights for Networks firewall rules found. Ensure the selected server role is correct and that the server software is installed.'
        Return

    }

    ForEach ($Rule in $Rules) {

        Write-Verbose "Updating firewall rule $($Rule.DisplayName)..."
        $Rule.Group = 'Absolute Secure Access'

        # Restrict firewall rule to the Windows domain profile if the server is domain-joined
        If ($DomainJoined) {

            Write-Verbose "Restricting firewall rule $($Rule.DisplayName) to domain profile..."
            $Rule.Profile = 'Domain'

        }

        $Rule | Set-NetFirewallRule

    }

}

# Clean up default Absolute Secure Access bandwidth test server firewall rule
If ($ServerRole -eq 'BandwidthTestServer') {

    Write-Verbose "Server role $ServerRole selected."
    $Rule = Get-NetFirewallRule -DisplayName 'Secure Access Bandwidth Server' -ErrorAction SilentlyContinue

    If ($Null -eq $Rule) {

        Write-Warning 'No Absolute Secure Access Bandwidth Test Server firewall rules found. Ensure the server role is correct and that the server software is installed.'
        Return

    }

    Write-Verbose "Updating firewall rule $($Rule.DisplayName)..."
    $Rule.Group = 'Absolute Secure Access'

    # Restrict firewall rule to the Windows domain profile if the server is domain-joined
    If ($DomainJoined) {

        Write-Verbose "Restricting firewall rule $($Rule.DisplayName) to domain profile..."
        $Rule.Profile = 'Domain'

    }

    $Rule | Set-NetFirewallRule

}

# SIG # Begin signature block
# MIInGQYJKoZIhvcNAQcCoIInCjCCJwYCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUM6NdbIOOzHAgEyMAl0IkeZzp
# u3mggiDBMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz
# 7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS
# 5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7
# bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfI
# SKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jH
# trHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14
# Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2
# h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt
# 6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPR
# iQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ER
# ElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4K
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRV
# HSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyh
# hyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO
# 0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo
# 8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++h
# UD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5x
# aiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGrjCCBJag
# AwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIw
# MzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQg
# UlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCw
# zIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFz
# sbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ
# 7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7
# QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/teP
# c5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCY
# OjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9K
# oRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6
# dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM
# 1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbC
# dLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbEC
# AwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1N
# hS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9P
# MA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcB
# AQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggr
# BgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7Zv
# mKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI
# 2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/ty
# dBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVP
# ulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmB
# o1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc
# 6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3c
# HXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0d
# KNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZP
# J/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLe
# Mt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDy
# Divl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrAwggSYoAMCAQICEAitQLJg0pxM
# n17Nqb2TrtkwDQYJKoZIhvcNAQEMBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UE
# AxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIxMDQyOTAwMDAwMFoXDTM2
# MDQyODIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBS
# U0E0MDk2IFNIQTM4NCAyMDIxIENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBANW0L0LQKK14t13VOVkbsYhC9TOM6z2Bl3DFu8SFJjCfpI5o2Fz16zQk
# B+FLT9N4Q/QX1x7a+dLVZxpSTw6hV/yImcGRzIEDPk1wJGSzjeIIfTR9TIBXEmtD
# mpnyxTsf8u/LR1oTpkyzASAl8xDTi7L7CPCK4J0JwGWn+piASTWHPVEZ6JAheEUu
# oZ8s4RjCGszF7pNJcEIyj/vG6hzzZWiRok1MghFIUmjeEL0UV13oGBNlxX+yT4Us
# SKRWhDXW+S6cqgAV0Tf+GgaUwnzI6hsy5srC9KejAw50pa85tqtgEuPo1rn3MeHc
# reQYoNjBI0dHs6EPbqOrbZgGgxu3amct0r1EGpIQgY+wOwnXx5syWsL/amBUi0nB
# k+3htFzgb+sm+YzVsvk4EObqzpH1vtP7b5NhNFy8k0UogzYqZihfsHPOiyYlBrKD
# 1Fz2FRlM7WLgXjPy6OjsCqewAyuRsjZ5vvetCB51pmXMu+NIUPN3kRr+21CiRshh
# WJj1fAIWPIMorTmG7NS3DVPQ+EfmdTCN7DCTdhSmW0tddGFNPxKRdt6/WMtyEClB
# 8NXFbSZ2aBFBE1ia3CYrAfSJTVnbeM+BSj5AR1/JgVBzhRAjIVlgimRUwcwhGug4
# GXxmHM14OEUwmU//Y09Mu6oNCFNBfFg9R7P6tuyMMgkCzGw8DFYRAgMBAAGjggFZ
# MIIBVTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRoN+Drtjv4XxGG+/5h
# ewiIZfROQjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8B
# Af8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdwYIKwYBBQUHAQEEazBpMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKG
# NWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290
# RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMBwGA1UdIAQVMBMwBwYFZ4EMAQMw
# CAYGZ4EMAQQBMA0GCSqGSIb3DQEBDAUAA4ICAQA6I0Q9jQh27o+8OpnTVuACGqX4
# SDTzLLbmdGb3lHKxAMqvbDAnExKekESfS/2eo3wm1Te8Ol1IbZXVP0n0J7sWgUVQ
# /Zy9toXgdn43ccsi91qqkM/1k2rj6yDR1VB5iJqKisG2vaFIGH7c2IAaERkYzWGZ
# gVb2yeN258TkG19D+D6U/3Y5PZ7Umc9K3SjrXyahlVhI1Rr+1yc//ZDRdobdHLBg
# XPMNqO7giaG9OeE4Ttpuuzad++UhU1rDyulq8aI+20O4M8hPOBSSmfXdzlRt2V0C
# FB9AM3wD4pWywiF1c1LLRtjENByipUuNzW92NyyFPxrOJukYvpAHsEN/lYgggnDw
# zMrv/Sk1XB+JOFX3N4qLCaHLC+kxGv8uGVw5ceG+nKcKBtYmZ7eS5k5f3nqsSc8u
# pHSSrds8pJyGH+PBVhsrI/+PteqIe3Br5qC6/To/RabE6BaRUotBwEiES5ZNq0RA
# 443wFSjO7fEYVgcqLxDEDAhkPDOPriiMPMuPiAsNvzv0zh57ju+168u38HcT5uco
# P6wSrqUvImxB+YJcFWbMbA7KxYbD9iYzDAdLoNMHAmpqQDBISzSoUSC7rRuFCOJZ
# DW3KBVAr6kocnqX9oKcfBnTn8tZSkP2vhUgh+Vc7tJwD7YZF9LRhbr9o4iZghurI
# r6n+lB3nYxs6hlZ4TjCCBsAwggSooAMCAQICEAxNaXJLlPo8Kko9KQeAPVowDQYJ
# KoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQTAeFw0yMjA5MjEwMDAwMDBaFw0zMzExMjEyMzU5NTla
# MEYxCzAJBgNVBAYTAlVTMREwDwYDVQQKEwhEaWdpQ2VydDEkMCIGA1UEAxMbRGln
# aUNlcnQgVGltZXN0YW1wIDIwMjIgLSAyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAz+ylJjrGqfJru43BDZrboegUhXQzGias0BxVHh42bbySVQxh9J0J
# dz0Vlggva2Sk/QaDFteRkjgcMQKW+3KxlzpVrzPsYYrppijbkGNcvYlT4DotjIdC
# riak5Lt4eLl6FuFWxsC6ZFO7KhbnUEi7iGkMiMbxvuAvfTuxylONQIMe58tySSge
# TIAehVbnhe3yYbyqOgd99qtu5Wbd4lz1L+2N1E2VhGjjgMtqedHSEJFGKes+JvK0
# jM1MuWbIu6pQOA3ljJRdGVq/9XtAbm8WqJqclUeGhXk+DF5mjBoKJL6cqtKctvdP
# bnjEKD+jHA9QBje6CNk1prUe2nhYHTno+EyREJZ+TeHdwq2lfvgtGx/sK0YYoxn2
# Off1wU9xLokDEaJLu5i/+k/kezbvBkTkVf826uV8MefzwlLE5hZ7Wn6lJXPbwGqZ
# IS1j5Vn1TS+QHye30qsU5Thmh1EIa/tTQznQZPpWz+D0CuYUbWR4u5j9lMNzIfMv
# wi4g14Gs0/EH1OG92V1LbjGUKYvmQaRllMBY5eUuKZCmt2Fk+tkgbBhRYLqmgQ8J
# JVPxvzvpqwcOagc5YhnJ1oV/E9mNec9ixezhe7nMZxMHmsF47caIyLBuMnnHC1mD
# jcbu9Sx8e47LZInxscS451NeX1XSfRkpWQNO+l3qRXMchH7XzuLUOncCAwEAAaOC
# AYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAf
# BgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUYore0GH8
# jzEU7ZcLzT0qlBTfUpwwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFt
# cGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVT
# dGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAVaoqGvNG83hXNzD8deNP
# 1oUj8fz5lTmbJeb3coqYw3fUZPwV+zbCSVEseIhjVQlGOQD8adTKmyn7oz/AyQCb
# Ex2wmIncePLNfIXNU52vYuJhZqMUKkWHSphCK1D8G7WeCDAJ+uQt1wmJefkJ5ojO
# fRu4aqKbwVNgCeijuJ3XrR8cuOyYQfD2DoD75P/fnRCn6wC6X0qPGjpStOq/CUkV
# NTZZmg9U0rIbf35eCa12VIp0bcrSBWcrduv/mLImlTgZiEQU5QpZomvnIj5EIdI/
# HMCb7XxIstiSDJFPPGaUr10CU+ue4p7k0x+GAWScAMLpWnR1DT3heYi/HAGXyRkj
# gNc2Wl+WFrFjDMZGQDvOXTXUWT5Dmhiuw8nLw/ubE19qtcfg8wXDWd8nYiveQclT
# uf80EGf2JjKYe/5cQpSBlIKdrAqLxksVStOYkEVgM4DgI974A6T2RUflzrgDQkfo
# QTZxd639ouiXdE4u2h4djFrIHprVwvDGIqhPm73YHJpRxC+a9l+nJ5e6li6FV8Bg
# 53hWf2rvwpWaSxECyIKcyRoFfLpxtU56mWz06J7UWpjIn7+NuxhcQ/XQKujiYu54
# BNu90ftbCqhwfvCXhHjjCANdRyxjqCU4lwHSPzra5eX25pvcfizM/xdMTQCi2NYB
# DriL7ubgclWJLCcZYfZ3AYwwggcCMIIE6qADAgECAhABZnISBJVCuLLqeeLTB6xE
# MA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25p
# bmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjExMjAyMDAwMDAwWhcNMjQx
# MjIwMjM1OTU5WjCBhjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEx
# FjAUBgNVBAcTDU1pc3Npb24gVmllam8xJDAiBgNVBAoTG1JpY2hhcmQgTS4gSGlj
# a3MgQ29uc3VsdGluZzEkMCIGA1UEAxMbUmljaGFyZCBNLiBIaWNrcyBDb25zdWx0
# aW5nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA6svrVqBRBbazEkrm
# htz7h05LEBIHp8fGlV19nY2gpBLnkDR8Mz/E9i1cu0sdjieC4D4/WtI4/NeiR5id
# tBgtdek5eieRjPcn8g9Zpl89KIl8NNy1UlOWNV70jzzqZ2CYiP/P5YGZwPy8Lx5r
# IAOYTJM6EFDBvZNti7aRizE7lqVXBDNzyeHhfXYPBxaQV2It+sWqK0saTj0oNA2I
# u9qSYaFQLFH45VpletKp7ded2FFJv2PKmYrzYtax48xzUQq2rRC5BN2/n7771NDf
# J0t8udRhUBqTEI5Z1qzMz4RUVfgmGPT+CaE55NyBnyY6/A2/7KSIsOYOcTgzQhO4
# jLmjTBZ2kZqLCOaqPbSmq/SutMEGHY1MU7xrWUEQinczjUzmbGGw7V87XI9sn8Ec
# WX71PEvI2Gtr1TJfnT9betXDJnt21mukioLsUUpdlRmMbn23or/VHzE6Nv7Kzx+t
# A1sBdWdC3Mkzaw/Mm3X8Wc7ythtXGBcLmBagpMGCCUOk6OJZAgMBAAGjggIGMIIC
# AjAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiIZfROQjAdBgNVHQ4EFgQUxF7d
# o+eIG9wnEUVjckZ9MsbZ+4kwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsG
# AQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIw
# MjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDA+
# BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRp
# Z2ljZXJ0LmNvbS9DUFMwgZQGCCsGAQUFBwEBBIGHMIGEMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYBBQUHMAKGUGh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNB
# NDA5NlNIQTM4NDIwMjFDQTEuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEL
# BQADggIBAEvHt/OKalRysHQdx4CXSOcgoayuFXWNwi/VFcFr2EK37Gq71G4AtdVc
# WNLu+whhYzfCVANBnbTa9vsk515rTM06exz0QuMwyg09mo+VxZ8rqOBHz33xZyCo
# Ttw/+D/SQxiO8uQR0Oisfb1MUHPqDQ69FTNqIQF/RzC2zzUn5agHFULhby8wbjQf
# Ut2FXCRlFULPzvp7/+JS4QAJnKXq5mYLvopWsdkbBn52Kq+ll8efrj1K4iMRhp3a
# 0n2eRLetqKJjOqT335EapydB4AnphH2WMQBHHroh5n/fv37dCCaYaqo9JlFnRIrH
# U7pHBBEpUGfyecFkcKFwsPiHXE1HqQJCPmMbvPdV9ZgtWmuaRD0EQW13JzDyoQdJ
# xQZSXJhDDL+VSFS8SRNPtQFPisZa2IO58d1Cvf5G8iK1RJHN/Qx413lj2JSS1o3w
# gNM3Q5ePFYXcQ0iPxjFYlRYPAaDx8t3olg/tVK8sSpYqFYF99IRqBNixhkyxAyVC
# k6uLBLgwE9egJg1AFoHEdAeabGgT2C0hOyz55PNoDZutZB67G+WN8kGtFYULBloR
# KHJJiFn42bvXfa0Jg1jZ41AAsMc5LUNlqLhIj/RFLinDH9l4Yb0ddD4wQVsIFDVl
# JgDPXA9E1Sn8VKrWE4I0sX4xXUFgjfuVfdcNk9Q+4sJJ1YHYGmwLMYIFwjCCBb4C
# AQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/
# BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYg
# U0hBMzg0IDIwMjEgQ0ExAhABZnISBJVCuLLqeeLTB6xEMAkGBSsOAwIaBQCgeDAY
# BgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3
# AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEW
# BBTQ6REuFzGISRNrwG/W4INBKm8I6zANBgkqhkiG9w0BAQEFAASCAYB/0SMn3eUc
# SttOvwjWfVnngmZ45TjhxdbFVknl58xygjsQyp2uGVW/aqxUcibGUeAq05xgUOdB
# FJoLcU6qgj1f91mZacHc8yJd6ihtIZa1MVqaOUsLhRIsVqWsYVgRdoMbc06Sb8Ry
# 0XRy5tgUmT5ZP4PUwZgz+8pHGul+1cG43DLpX2GuytYh5leefs/BQnSYEMf2Eja4
# 4oCB+v2fIEfFdbgdvKjHgw5O8Grsq8280Pi3EXOXYg0+BuuNcoHN++APrCrByjtR
# m6J6IqwP08QZ9EDuiDTTPR+1l0X1ve6Uwf0X8+r/sGD6NennxWuS0mhx6c9KdKv2
# LZ8pL/7MQbxxcxeFTA9xyQo5k0presE2Xxoj/XbmBX0hlaxxm3l451PYdYHP7MYk
# EIhowJsDevPxjG9httklZiOKL6uGZyZ10UsXSJ0HyjaAhntvQkuI+ZEc86axuzpL
# w3S4alz+KoCihCJU1/qec+ZY7pG/0ewrAJDcc4SH8RNCfVaN/XxdlNShggMgMIID
# HAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQg
# UlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAMTWlyS5T6PCpKPSkHgD1a
# MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkq
# hkiG9w0BCQUxDxcNMjMwODAzMDQyNjEzWjAvBgkqhkiG9w0BCQQxIgQggHdNbfNY
# /NvuY5QB1wKjxt/Cxw/3FBTmlDFlHbiK498wDQYJKoZIhvcNAQEBBQAEggIADdmM
# mSX4uXmOGn92vWFunsq5t3UxQOJeS5VI2y9hKSmtKs/zPodgJoByFoKSi7C4FNJx
# AqhvISgk23vStO6IlJsU4O4F6qOznRT+1izI/1EGtxELFjAnEXxV3cdt3hNQYnlt
# qMG4Qz7XM5AIhfbffgqnvUOBiqqqkameDZoeHULrE2OuCSOMfU3Ib5aiPFZsIAQM
# mV6JVXrM0QBQEQXgNuInD0GvpMpsyHIVSYNT4sZr9w1Zq0xsCflwG3aJJwaVo7Hg
# LnKd8BWWDXVaev/tplreM7OvmjCdKx0/12d1S/NhFXrcdqPjBzt5Owx0qJRuS+lG
# LQUNN6T7T6V34MGbt4YsanI3OvLLzQi2LwKIoW6CKy0dio61qhjKhof0fhsH6QDU
# Za4mCVi4fUPxpoyBOZHR6bzxw3UDJacMOZhxyIXqlHyASRWbMT49Mv4bIsYAkwZr
# ng5ZPtOvuBruqrpLXRQZUoSnIolEp91cS8ZRZC/6t+0Fz5DkQKYNi0AbD1VQGvGQ
# OnLSv7up9clbFutvw6YAcN5mvHPdCpU/WfzmEPIvpL6nWqLLyybhba9va829qzQC
# DnbvN/cdkNc7XiFLiSFXVtH65H5AlJtSa02iwQZ0ZMlfvQq03Xg526nCpYIdfoIa
# 24rO3XyZVYZ4565t7GoKaQqfO1wl5bzVzSgSYLU=
# SIG # End signature block
