<#
.SYNOPSIS
Generates a random string of 12 characters based on specified criteria such as which character sets are required.

.DESCRIPTION
This function, New-RandomString.ps1, generates a fixed length string of 12 characters, consisting of a set of character types that you specify, such as uppercase, lowercase,
numbers and special characters. It is convenient to generate random strings multiple times from the same script, but with different character set combinations.
Some scenarios for which this function can be used includes; For passwords. In Azure, a minimum password length of 12 characters is required,
also Azure storage account names only accept lowercase and numeric characters, and Azure Site-To-Site VPN shared keys do not accept special characters.

.EXAMPLE
New-RandomString

.EXAMPLE
New-RandomString -IncludeUpper -IncludeLower -IncludeNumbers -IncludeSpecial

.PARAMETER -IncludeUpper
Include upper case letters. This parameter is an optional switch

.PARAMETER -IncludeLower
Include lower case letters. This parameter is an optional switch

.PARAMETER -IncludeNumbers
Include numeric characters. This parameter is an optional switch

.PARAMETER -IncludeSpecial
Include special characters. This parameter is an optional switch

.INPUTS
[int]
[boolean]

.OUTPUTS
[string]

.NOTES
NAME: New-RandomString

REQUIREMENTS:
-Version 5.0

AUTHOR: Preston K. Parsard

ATTRIBUTION:
NA

LASTEDIT: 06 DEC 2016

KEYWORDS: Random, String, Passwords, Complexity

LICENSE:
The MIT License (MIT)
Copyright (c) 2016 Preston K. Parsard

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

DISCLAIMER:
THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive,
royalty-free right to use and modify the Sample Code and to reproduce and distribute the Sample Code, provided that You agree: (i) to not use Our name,
logo, or trademarks to market Your software product in which the Sample Code is embedded;
(ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless,
and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ fees,
that arise or result from the use or distribution of the Sample Code.

.LINK
https://technet.microsoft.com/en-us/ms376608.aspx
#>

<# WORK ITEMS
TASK-INDEX: 000
#>

<#
**************************************************************************************************************************************************************************
REVISION/CHANGE RECORD
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------
DATE         VERSION    NAME			     CHANGE
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------
12 NOV 2016  01.0.00.00 Preston K. Parsard Initial release
06 DEC 2016  01.0.00.00 Preston K. Parsard Minor corrections in description and tagged help fields
#>

# Function to create a random string of 12 characters from each of the password complexity requirements set (Uppercase, Lowercase, Special and Numeric)
Function New-RandomString
{
 [CmdletBinding(SupportsShouldProcess=$true,
  PositionalBinding=$false,
  HelpUri = 'https://gallery.technet.microsoft.com/scriptcenter',
  ConfirmImpact='Medium')]
 [OutputType([String])]
 Param
 (
  # Uppercase characters
  [switch] $IncludeUpper,

  # Lowercase characters
  [switch] $IncludeLower,

  # Numeric characters
  [switch] $IncludeNumbers,

  # Special characters
  [switch] $IncludeSpecial
 )

 # Lenth of random string
 [int]$StringLength = 12
 # Initialize array that will contain the custom combination of upper, lower, numeric and special complexity rules characters
 [string]$CharArray = @()
 # Initialize array of the default complexity rule set (uppercase, lowercase, numerical)
 [array]$RuleSets = @()
 # Initialize constructed string consisting of up to 12 characters, with characters from each of the 4 complexity rules
 [array]$StringArray = @()
 # The default number of samples taken from each of 3 complexity rules (Upper, Lower and Numeric) to construct the generated password string. SCR = String Complexity Rule.
 [int]$SampleCount = 0
 # Represents the combination of options selected: i.e. U = uppercase, L = lowercase, N = numeric and S = special. If all 4 options are selected, then the value of $Switches will be ULNS.
 [string]$Switches = $null

 # Alphabetic uppercase complexity rule
 $SCR1AlphaUpper = ([char[]]([char]65..[char]90))
 # Alphabetic lowercase complexity rule
 $SCR2AlphaLower = ([char[]]([char]97..[char]122))
 # Numeric complexity rule
 $SCR3Numeric = ([char[]]([char]48..[char]57))
 # Special characters complexity rule
 $SCR4Special = ([char[]]([char]33..[char]47)) + ([char[]]([char]58..[char]64)) + ([char[]]([char]92..[char]95)) + ([char[]]([char]123..[char]126))

 # Combine all complexity rules arrays into one consolidated array for all possible character values

 # Detect which switch parameters were used
 If ($IncludeUpper) { $Switches = "U" }
 If ($IncludeLower) { $Switches += "L" }
 If ($IncludeNumbers) { $Switches += "N" }
 If ($IncludeSpecial) { $Switches += "S" }

 If ($Switches.Length -gt 0)
 {
  # Calculate # of characters to sample per rule set
  [int]$SampleCount = $StringLength/($Switches.Length)
   Switch ($Switches)
   {
    # Alphabetic uppercase complexity rule
    {$_ -match 'U'}
    {
     Get-Random -InputObject $SCR1AlphaUpper -Count $SampleCount | ForEach-Object { $StringArrayU += $_ }
     $StringArray += $StringArrayU
    } #end -match

    # Alphabetic lowercase complexity rule
    {$_ -match 'L'}
    {
     Get-Random -InputObject $SCR2AlphaLower -Count $SampleCount | ForEach-Object { $StringArrayL += $_ }
    $StringArray += $StringArrayL
    } #end -match

    # Numeric complexity rule
    {$_ -match 'N'}
    {
     Get-Random -InputObject $SCR3Numeric -Count $SampleCount | ForEach-Object { $StringArrayN += $_ }
     $StringArray +=  $StringArrayN
    } #end -match

    # Special characters complexity rule
    {$_ -match 'S'}
    {
     Get-Random -InputObject $SCR4Special -Count $SampleCount | ForEach-Object { $StringArrayS += $_ }
     $StringArray +=  $StringArrayS
    } #end -match
   } #end Switch
 } #end If
 Else
 {
  # No options were specified
  [int]$SampleCount = 4
  [string]$CharArray = $SCR1AlphaUpper + $SCR2AlphaLower + $SCR3Numeric
  # Construct an array of 3 complexity rule sets
  [array]$RuleSets = ($SCR1AlphaUpper, $SCR2AlphaLower, $SCR3Numeric)
  # Generate a specified set of characters from each of the 4 complexity rule sets
  ForEach ($RuleSet in $RuleSets)
  {
   Get-Random -InputObject $RuleSet -Count $SampleCount | ForEach-Object { $StringArray += $_ }
  } #end ForEach
 } #end Else

 [string]$RandomStringWithSpaces = $StringArray
 $RandomString = $RandomStringWithSpaces.Replace(" ","")
 Write-Host "`$Switches selected: $Switches"
 Write-Host  "Randomly generated 12 character string: " $RandomString
 return $RandomString
} #end Function