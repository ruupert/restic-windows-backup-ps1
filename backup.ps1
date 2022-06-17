
##### MOTES

## When backing up MSSQL databases, make sure the user this script is run as has backup role operator for the databases to be backed up.

## Should work with 2012r2, 2016, 2019 server relases.

##########################################################################################
############################## Configuration start #######################################
##########################################################################################


# Which drive and dir to use for backup files
$backup_drive = "D:"

# Backup directory name for temporary files / staging

$backup_dir = "examplebackupdir"   # Make sure that the local user which runs the script has full permissions to the directory


# Restic variables

# The base64 allows just embedding the password file in this script ... not at all secure.

# Creating a base64 encoded representation of the restic repository password file:
# echo "randompassword" > C:\path\to\my\file
# $Content = Get-Content -Path C:\path\to\my\file -Encoding Byte
# $Base64 = [System.Convert]::ToBase64String($Content)
# $Base64 | Out-File C:\path\to\my\file.encoded.txt
# or just "write-output $Base64" and set that as the $restic_pwfile_Base64 variable.

$restic_pwfile_Base64 = ""
$restic_tmp_pwfile = [System.Convert]::FromBase64String($restic_pwfile_Base64)
Set-Content -Path "$($backup_drive)\$($backup_dir)\resticpw" -Value $restic_tmp_pwfile -Encoding Byte

$restic_exe_fname = "restic_0.9.5_windows_amd64.exe"

# Restic executable path
$restic_exe = "$($backup_drive)\$($backup_dir)\$($restic_exe_fname)"
$restic_pwfile = "$($backup_drive)\$($backup_dir)\resticpw"

# Restic repository user and repository name
$restic_user = ""
# Restic REST htacces password
$restic_htaccess = ""

# Restic rest-repository
#
# format as "host:port"
$restic_rest_host = ""

## MSSQL specific
#
# for local backup user: Grant-ClusterAccess -User hostname\backup -readonly


# tells this script that it is working with an availability group. Backup should happen only on the primary node.
$ha_mode = $true

# Availability group name
$availability_group = ""

## Prometheus
#
# Not implemented but the idea was to write metrics about job success / failure.

$wmi_export_textfile = "C:\Program Files\wmi_exporter\textfile_inputs\restic.prom"



##########################################################################################
################################ CONFIGURATION END #######################################
##########################################################################################

# Defaults 
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

$restic_directories = New-object System.Collections.ArrayList

# object types

class DatabaseEntity {
    [string]$Instance
    [string]$Name
    [long]$Size
    [int]$Success
}
$databases_entries = New-object System.Collections.ArrayList


function BackupDrive {
    $wmiobj = Get-WmiObject -Class Win32_logicaldisk
    foreach ($obj in $wmiobj) { 
	   if ($obj.DeviceID -like $backup_drive) {
		Write-Output "Backup drive exists"
	    return $true 
	   } 
	}
	Write-Output "ERROR: Backup drive does not exist"
    return $false

}

function WMI_exporter_textfile {
    Remove-Item -Force $wmi_export_textfile
    New-Item $wmi_export_textfile
    $acl = Get-Acl $wmi_export_textfile
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "Allow") # just for debugging... 
    $acl.SetAccessRule($AccessRule)
    $acl | Set-Acl $wmi_export_textfile
    Write-Output $wmi_export_textfile
    return $true    
}

function ResticBackup {

	Write-Output "Starting Restic Backup"
    $restic_repository = "rest:http://$($restic_user):$($restic_htaccess)@$($restic_rest_host)/$($restic_user)"

    Start-Process -Wait -NoNewWindow -FilePath "$($restic_exe)" -ArgumentList "-r $($restic_repository) unlock -p $($restic_pwfile)"

	
    foreach ( $dir in $restic_directories ) {
        Write-Output "Backing up directory $dir"
        $dir = $dir -replace ' ','` '
        Start-Process -Wait -NoNewWindow -FilePath "$($restic_exe)" -ArgumentList "-r $($restic_repository) backup $($dir) --password-file $($restic_pwfile) --tag Files_$($dir)"

    }
    Start-Process -Wait -NoNewWindow -FilePath "$($restic_exe)" -ArgumentList "-r $($restic_repository) unlock -p $($restic_pwfile)"
    Start-Process -Wait -NoNewWindow -FilePath "$($restic_exe)" -ArgumentList "-r $($restic_repository) forget --keep-hourly 8 --keep-daily 7 --keep-weekly 5 --keep-monthly 12 --keep-yearly 75 --prune  --password-file $($restic_pwfile)"

    #Remove-Item $restic_pwfile
	
}


function hasIIS {
    if ((Get-WindowsFeature Web-Server).InstallState -eq "Installed") {
        return $true
    } 
    else {
        return $false
    }
}

function hasMSSQL {
    if (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {
        Import-Module "sqlps" -DisableNameChecking  
        return $true
    }
    else {
        return $false
    }
}

# Stupid but checks in three ways: Is "WMI Exporter" product installed and is service "wmi_exporter" present and is the service in "Running" state
function hasWMIExporter {
    $products = (Get-WmiObject -Class Win32_Product | select name)
    foreach ($product in $products) {
        if ($product.Name -match "WMI Exporter") {
            foreach ($service in (Get-Service | select Status, Name)) { if ($service.Name -match "wmi_exporter") { if ($service.Status -match "Running") { return $true } } }
        }
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    #  Invoke-WebRequest -URI https://github.com/martinlindhe/wmi_exporter/releases/download/v0.8.3/wmi_exporter-0.8.3-amd64.msi -OutFile "$backup_drive\$backup_dir\wmi_exporter.msi"
    #  msiexec.exe /i "$backup_drive\$backup_dir\wmi_exporter.msi"
    #  if (!$?) {
    #      return $false
    # }
    # else {
    #     
    #     return hasWMIExporter
    # }
}

# Checks if restic is available at the specified backup drive root. If not then download it from github and unpack and call self to get the true return value.
function hasRestic {
    if ([System.IO.File]::Exists("$($restic_exe)")) {
		Write-Output "Resitc found"
        return $true
    }
    else {
        # double check that there is a backup drive 
        if (BackupDrive) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
			Write-Output "Downloading Restic"
            Invoke-WebRequest -URI https://github.com/restic/restic/releases/download/v0.9.5/restic_0.9.5_windows_amd64.zip -OutFile "$backup_drive\restic.zip"
            Expand-Archive -Path "$backup_drive\restic.zip" -DestinationPath "$backup_drive\"
            
            return hasRestic  # recursion loop risk
        }
        else {
			Write-Output "Restic does not exist"
            return $false
        }
    }
}


# Prepare ceritficate store backup by dumping the certificates to the disk
function BackupCertificates {


    $cert_backup_dir = "$($backup_drive)\$($backup_dir)\cert"
	
	Write-Output "Exporting certificates to $($cert_backup_dir)"
	
    New-Item -ItemType Directory -Force -Path $cert_backup_dir > $null


    $certs_stores = get-childitem -path cert:\LocalMachine -Name 
    $type = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert 

    ForEach ($store in $certs_stores) {
        $cpath = "cert:\LocalMachine\" + $store
        $certs = get-childitem -path $cpath
        $mkdir = "$cert_backup_dir\" + $store
        New-Item -ItemType Directory -Force -Path $mkdir > $null
        foreach ($cert in $certs) {
            $hash = $cert.GetCertHashString()
            $path = "$cert_backup_dir\" + $store + "\" + $hash + ".der"
            [System.IO.File]::WriteAllBytes($path, $cert.export($type) )
        } 

    }
	Write-Output "Certificate export complete. Adding $($cert_backup_dir) to list of dirs to be backed up"
    $restic_directories.add("$($cert_backup_dir)")
    
}



# Prepare MSSSQL backup by dumping the databases.
#
# Named pipes were not available in MSSQL so no direct backup to repository :( 
# 
# Issue here is the estimation of how much disk space is needed for the backup to succeed. 
# Database gives a value but when dumping with compression it can be less, way less or way way less in actual total size once dumped.

function BackupMsSQL {


    $db_backup_dir = "$($backup_drive)\$($backup_dir)\db"
    New-Item -ItemType Directory -Force -Path $db_backup_dir > $null


    $hostname = $env:computername 
    $instances = Get-ChildItem -Path "SQLSERVER:\SQL\$hostname" -Name

    Remove-Item "$db_backup_dir\*.bak"
	Write-Output "Dumping MSSQL databases to $($db_backup_dir)"
	
    foreach ($instance in $instances) {
        $instancepath = "SQLSERVER:\SQL\$hostname\$instance\Databases"
        $databases = Get-ChildItem -Path $instancepath -Name
        $disk_required = Get-ChildItem -Path $instancepath | select Size | Measure-Object -Property Size -Sum | select sum
        # Need to remove old backup files to be able to get the free space.
        $wmiobj = Get-WmiObject -Class Win32_logicaldisk

        $free_space = foreach ($obj in $wmiobj) { if ($obj.DeviceID -like $backup_drive) { Write-Output $obj.FreeSpace } }
        $free_space = ($free_space / 1024 / 1024 )
        $free_space = [math]::Round($free_space)
        Write-Output $free_space
        Write-Output $disk_required

        foreach ($database in $databases) {
                $dbName = $instance + "_" + $database
                Write-Output $dbName
                $db_entry = [DatabaseEntity]::new()
                Backup-SqlDatabase -CompressionOption On -Path $instancepath -Database $database -BackupAction Database -BackupFile "$db_backup_dir\$dbName.bak" -OutVariable $db_entry.Success
                $db_entry.Instance = $instance
                $db_entry.Name = $database
                $db_entry.Size = (Get-Item "$db_backup_dir\$dbName.bak").Length
                Write-Output "-----"
                Write-Output $db_entry 
                Write-Output "-----"
                $databases_entries.Add($db_entry)


        }
        else {
            #should indicate a failure here
            Write-Output "Not enough disk space to backup. Required $disk_required.sum but only $free_space available" 
            return 2
        }
		Write-Output "Dump complete and adding $($db_backup_dir) to list of directories to be backed up"
        # continue with restic backup and and as database
        $restic_directories.Add("$($db_backup_dir)");

        return 1
    }

}

# Prepare IIS to be backed up.
# 
# configs and inetpubs

function BackupIIS {

	Write-Output "Export IIS site configurations"
    # since we are using restic differential backups no need to different names:
    $backupname = "configurationBackup"
    Remove-WebConfigurationBackup -Name $backupname
    # creates a backup to C:\Windows\System32\inetsrv\backup
    Backup-WebConfiguration -Name $backupname
    if (!$?) {
        Write-Output "Failed to backup IIS webConfiguration" 
        return 0 
    }

    # Append to restic directories to be backed up
    $restic_directories.Add("C:\Windows\System32\inetsrv\backup")

    # Get sites
    $sites = Get-Website
    foreach ($site in $sites) {
        $dir = $site.physicalPath
        Write-Output "Adding $dir to be backed up"
        $restic_directories.Add("$($dir)")        
    }


    
}

#### START
#
# This part is the execution logic:


#Start-Transcript -path $($backup_drive)\$($backup_dir)\output.log -append
if (BackupDrive) {
    if (hasRestic) {

        New-Item -ItemType Directory -Force -Path $backup_dir  > $null
        Write-Output $backup_dir

        BackupCertificates    
        
        if (hasIIS -eq $true) {
            BackupIIS             
        }   
        if (hasMSSQL -eq $true) { 
            if ($ha_mode -eq $true) {
            Write-Output "SQLServer in HA mode"
                $AGPrimary = get-clusterresource -name $availability_group |  Select -ExpandProperty OwnerNode
                If ($AGPrimary -eq $env:COMPUTERNAME) {
                    write-output "$env:COMPUTERNAME is primary, proceeding with with backup."
                   BackupMsSQL
                   ResticBackup
                } else {
                    write-output "$env:COMPUTERNAME not primary, aborting backup on this host. Primary is $AGPrimary"
                }
            } else {
               
               BackupMsSQL
            }           
		}

        
        if ($ha_mode -eq $false) {
            ResticBackup
        }
      #  Remove-Item $restic_pwfile
    }
}

#Stop-Transcript


# Testing just:

function reportToPrometheus {

    $val = hasWMIExporter
    Write-Output $val
    if (hasWMIExporter) {
        if (WMI_exporter_textfile) {
            # output path format incorrect... :D creating a new branch here for development and later fastforward merge to master.
            $cer = $certficicates_present + $certificates_success
            write-output $wmi_export_textfile
            Write-Output "restic_backup_state{application=""certificates""} $cer" | Out-File -FilePath "$wmi_export_textfile" -Append
            Write-Output "restic_backup_size{application=""certificates""} $certificates_size" | Out-File -FilePath  "$wmi_export_textfile" -Append

            if (hasIIS) {
                Write-Output "restic_backup_state{application=""iis""} ($iis_res)" | Out-File -FilePath  "$wmi_export_textfile" -Append
                Write-Output "restic_backup_size{application=""iis""} $iis_size" | Out-File -FilePath  "$wmi_export_textfile" -Append
            }

            if (hasMSSQL) {
                Write-Output "restic_backup_state{application=""mssql""} ($mssql_res)" | Out-File -FilePath  "$wmi_export_textfile" -Append
                Write-Output "restic_backup_size{application=""mssql""} $mssql_size" | Out-File -FilePath  "$wmi_export_textfile" -Append
            }

        }
    }
    else {
        write-output "no wmi"

    }
}