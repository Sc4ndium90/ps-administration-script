Add-Type -AssemblyName System.Windows.Forms

# Function for success message
function Show-SuccessMessage {
    # Create the GUI form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Success"
    $form.Size = New-Object System.Drawing.Size(320, 100)
    $form.StartPosition = "CenterScreen"

    # Create the label for success message
    $successLabel = New-Object System.Windows.Forms.Label
    $successLabel.Location = New-Object System.Drawing.Point(10, 20)
    $successLabel.Size = New-Object System.Drawing.Size(280, 20)
    $successLabel.Text = "Action successful!"
    $form.Controls.Add($successLabel)

    # Create the button
    $button = New-Object System.Windows.Forms.Button
    $button.Location = New-Object System.Drawing.Point(100, 50)
    $button.Size = New-Object System.Drawing.Size(100, 30)
    $button.Text = "OK"
    $button.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $button
    $form.Controls.Add($button)

    # Show the form
    $form.ShowDialog()
}


# Function for error message (with custom message)
function Show-ErrorMessage {
    param (
        [Parameter(Mandatory = $true)]
        [string]$message
    )

    # Create the GUI form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Error"
    $form.Size = New-Object System.Drawing.Size(320, 100)
    $form.StartPosition = "CenterScreen"

    # Create the label for error message
    $errorLabel = New-Object System.Windows.Forms.Label
    $errorLabel.Location = New-Object System.Drawing.Point(10, 20)
    $errorLabel.Size = New-Object System.Drawing.Size(280, 20)
    $errorLabel.Text = $message
    $form.Controls.Add($errorLabel)

    # Create the button
    $button = New-Object System.Windows.Forms.Button
    $button.Location = New-Object System.Drawing.Point(100, 50)
    $button.Size = New-Object System.Drawing.Size(100, 30)
    $button.Text = "OK"
    $button.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $button
    $form.Controls.Add($button)

    # Show the form
    $form.ShowDialog()
}

# Define the actions
$actions = [ordered]@{
    "1.1" = "Delete all network drives"
    "1.2" = "Map a network drive"

    "2.1" = "Stop and disable telemetry service"
    "2.2" = "Stop and disable Windows Update service"

    "3.1" = "Sleep after XX mins"
    "3.2" = "Disable deep sleep"
    "3.3" = "Enable numlock on startup"
    "3.4" = "Enable recycle bin deletion confirmation"
    "3.5" = "Explorer - Show hidden files"
    "3.6" = "Explorer - Show files extensions"
    "3.7" = "IE - Default page to www.google.fr"
    "3.8" = "Delete Windows Store app"

    "4.1" = "IP Configuration"
    "4.2" = "DNS Configuration"

    "5.1" = "Show logs"
    "5.2" = "Show Windows version"

    "6.1" = "Create AD accounts to specific server with CSV files"
}

$continueLoop = $true

while ($continueLoop) {
    # Create the GUI form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Action Selection"
    $form.Size = New-Object System.Drawing.Size(320, 200)
    $form.StartPosition = "CenterScreen"

    # Create the label
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10, 20)
    $label.Size = New-Object System.Drawing.Size(280, 20)
    $label.Text = "Please select an action:"
    $form.Controls.Add($label)

    # Create the combobox
    $comboBox = New-Object System.Windows.Forms.ComboBox
    $comboBox.Location = New-Object System.Drawing.Point(10, 50)
    $comboBox.Size = New-Object System.Drawing.Size(280, 20)

    # Add the actions to the combobox
    foreach ($action in $actions.GetEnumerator()) {
        $comboBox.Items.Add($action.Key + " : " + $action.Value)
    }

    $form.Controls.Add($comboBox)

    # Create the button
    $button = New-Object System.Windows.Forms.Button
    $button.Location = New-Object System.Drawing.Point(100, 100)
    $button.Size = New-Object System.Drawing.Size(100, 30)
    $button.Text = "OK"
    $button.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $button
    $form.Controls.Add($button)

    # Show the form and get the selected action
    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $selectedAction = $comboBox.SelectedItem.ToString().Split(":")[0].Trim()
        # Perform the selected action
        
        switch ($selectedAction) {
            "1.1" {
                $networkDrives = Get-PSDrive -PSProvider FileSystem | Where-Object {$_.DisplayRoot -like '\\*'}
                foreach ($drive in $networkDrives) {
                    Remove-PSDrive -Name $drive.Name -Force
                }

                Show-SuccessMessage
            }
            "1.2" {

                # Create the GUI form
                $form = New-Object System.Windows.Forms.Form
                $form.Text = "Drive Mapping"
                $form.Size = New-Object System.Drawing.Size(380, 200)
                $form.StartPosition = "CenterScreen"

                # Create the label for drive letter
                $driveLabel = New-Object System.Windows.Forms.Label
                $driveLabel.Location = New-Object System.Drawing.Point(10, 20)
                $driveLabel.Size = New-Object System.Drawing.Size(280, 20)
                $driveLabel.Text = "Enter the drive letter (e.g., Z):"
                $form.Controls.Add($driveLabel)

                # Create the textbox for drive letter
                $driveTextBox = New-Object System.Windows.Forms.TextBox
                $driveTextBox.Location = New-Object System.Drawing.Point(10, 50)
                $driveTextBox.Size = New-Object System.Drawing.Size(280, 20)
                $form.Controls.Add($driveTextBox)

                # Create the label for network path
                $pathLabel = New-Object System.Windows.Forms.Label
                $pathLabel.Location = New-Object System.Drawing.Point(10, 80)
                $pathLabel.Size = New-Object System.Drawing.Size(280, 20)
                $pathLabel.Text = "Enter the network path (e.g., \\server\share):"
                $form.Controls.Add($pathLabel)

                # Create the textbox for network path
                $pathTextBox = New-Object System.Windows.Forms.TextBox
                $pathTextBox.Location = New-Object System.Drawing.Point(10, 110)
                $pathTextBox.Size = New-Object System.Drawing.Size(280, 20)
                $form.Controls.Add($pathTextBox)

                # Create the button
                $button = New-Object System.Windows.Forms.Button
                $button.Location = New-Object System.Drawing.Point(100, 150)
                $button.Size = New-Object System.Drawing.Size(100, 30)
                $button.Text = "OK"
                $button.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $form.AcceptButton = $button
                $form.Controls.Add($button)

                # Show the form and get the drive letter and network path
                $result = $form.ShowDialog()

                if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                    $driveLetter = $driveTextBox.Text.Trim()
                    $networkPath = $pathTextBox.Text.Trim()

                    # Check if the drive letter is already used, if error use the function Show-ErrorMessage
                    if (Get-PSDrive -Name $driveLetter -ErrorAction SilentlyContinue) {
                        Show-ErrorMessage -message "The drive letter is already used!"
                    } else {
                        # Perform the drive mapping
                        New-PSDrive -Name $driveLetter -PSProvider FileSystem -Root $networkPath -Persist -Scope Global
                    
                        # Check if drive mapping is successful, if success use the function Show-SuccessMessage
                        if (Get-PSDrive -Name $driveLetter -ErrorAction SilentlyContinue) {
                            Show-SuccessMessage
                        } else {
                            Show-ErrorMessage -message "The drive mapping failed!"
                        }

                    }
                }
                                
            }

            "2.1" {
                # Stop and disable telemetry
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
                Stop-Service -Name "DiagTrack" -Force
                Set-Service -Name "DiagTrack" -StartupType Disabled

                # Stop and disable connected user experience
                Stop-Service -Name "UsoSvc" -Force
                Set-Service -Name "UsoSvc" -StartupType Disabled

                # Check if the services are stopped and disabled, if success use the function Show-SuccessMessage
                if ((Get-Service -Name "DiagTrack").Status -eq "Stopped" -and (Get-Service -Name "UsoSvc").Status -eq "Stopped") {
                    Show-SuccessMessage
                } else {
                    Show-ErrorMessage -message "All or some services are not stopped and disabled!"
                }
            }
            "2.2" {
                # Stop and disable Windows Update service
                Stop-Service -Name "wuauserv" -Force
                Set-Service -Name "wuauserv" -StartupType Disabled

                # Check if the service is stopped and disabled, if success use the function Show-SuccessMessage
                if ((Get-Service -Name "wuauserv").Status -eq "Stopped") {
                    Show-SuccessMessage
                } else {
                    Show-ErrorMessage -message "The service is not stopped and disabled!"
                }
            }

            "3.1" {
                #Ask for AFK time before going in sleep
                $afkTime = Read-Host "Enter the AFK time minimum before for sleep mode"
                Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value $afkTime
            
                # Set the registry value to enable sleep mode
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -Value 1

                # Check if the registry value is set, if success use the function Show-SuccessMessage
                if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled").HibernateEnabled -eq 1) {
                    Show-SuccessMessage
                } else {
                    Show-ErrorMessage -message "The registry value is not set!"
                }
            }

            "3.2" {
                # Disable deep sleep
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "CsEnabled" -Value 0
            
                # Check if the registry value is set, if success use the function Show-SuccessMessage
                if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "CsEnabled").CsEnabled -eq 0) {
                    Show-SuccessMessage
                } else {
                    Show-ErrorMessage -message "The registry value is not set!"
                }
            
            }


            "3.3" {
                # Enable numlock on startup
                Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Value 2
            
                # Check if the registry value is set, if success use the function Show-SuccessMessage
                if ((Get-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "InitialKeyboardIndicators").InitialKeyboardIndicators -eq 2) {
                    Show-SuccessMessage
                } else {
                    Show-ErrorMessage -message "The registry value is not set!"
                }
            
            }

            "3.4" {
                # Enable recycle bin confirmation
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ConfirmFileDelete" -Value 1
            
                # Check if the registry value is set, if success use the function Show-SuccessMessage
                if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ConfirmFileDelete").ConfirmFileDelete -eq 1) {
                    Show-SuccessMessage
                } else {
                    Show-ErrorMessage -message "The registry value is not set!"
                }
            
            }

            "3.5" {
                # Set the registry value to show hidden files
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1

                # Refresh the explorer to apply the changes
                $explorerProcess = Get-Process -Name "explorer"
                $explorerProcess.Refresh()

                # Check if the registry value is set, if success use the function Show-SuccessMessage
                if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden").Hidden -eq 1) {
                    Show-SuccessMessage
                } else {
                    Show-ErrorMessage -message "The registry value is not set!"
                }
            }

            "3.6" {
                # Set the registry value to show file extensions
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0

                # Refresh the explorer to apply the changes
                $explorerProcess = Get-Process -Name "explorer"
                $explorerProcess.Refresh()

                # Check if the registry value is set, if success use the function Show-SuccessMessage
                if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt").HideFileExt -eq 0) {
                    Show-SuccessMessage
                } else {
                    Show-ErrorMessage -message "The registry value is not set!"
                }
            }

            "3.7" {
                # Set the default page on Internet Explorer
                $ieStartPage = "www.google.fr"
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name "Start Page" -Value $ieStartPage
                
                # Check if the registry value is set, if success use the function Show-SuccessMessage
                if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name "Start Page")."Start Page" -eq $ieStartPage) {
                    Show-SuccessMessage
                } else {
                    Show-ErrorMessage -message "The registry value is not set!"
                }
            }

            "3.8" {
                Get-AppxPackage *windowsstore* | Remove-AppxPackage

                # Check if the Windows Store app is deleted, if success use the function Show-SuccessMessage
                if ((Get-AppxPackage *windowsstore*).Count -eq 0) {
                    Show-SuccessMessage
                } else {
                    Show-ErrorMessage -message "The Windows Store app is not deleted!"
                }
            }

            "4.1" {
                Add-Type -AssemblyName System.Windows.Forms

                # Create a form
                $form = New-Object System.Windows.Forms.Form
                $form.Text = "Network Configuration"
                $form.Size = New-Object System.Drawing.Size(300, 200)
                $form.StartPosition = "CenterScreen"

                # Create IP address label and textbox
                $ipLabel = New-Object System.Windows.Forms.Label
                $ipLabel.Text = "IP Address:"
                $ipLabel.Location = New-Object System.Drawing.Point(20, 20)
                $form.Controls.Add($ipLabel)

                $ipTextBox = New-Object System.Windows.Forms.TextBox
                $ipTextBox.Location = New-Object System.Drawing.Point(120, 20)
                $form.Controls.Add($ipTextBox)

                # Create subnet mask label and textbox
                $subnetLabel = New-Object System.Windows.Forms.Label
                $subnetLabel.Text = "Subnet Mask:"
                $subnetLabel.Location = New-Object System.Drawing.Point(20, 60)
                $form.Controls.Add($subnetLabel)

                $subnetTextBox = New-Object System.Windows.Forms.TextBox
                $subnetTextBox.Location = New-Object System.Drawing.Point(120, 60)
                $form.Controls.Add($subnetTextBox)

                # Create default gateway label and textbox
                $gatewayLabel = New-Object System.Windows.Forms.Label
                $gatewayLabel.Text = "Default Gateway:"
                $gatewayLabel.Location = New-Object System.Drawing.Point(20, 100)
                $form.Controls.Add($gatewayLabel)

                $gatewayTextBox = New-Object System.Windows.Forms.TextBox
                $gatewayTextBox.Location = New-Object System.Drawing.Point(120, 100)
                $form.Controls.Add($gatewayTextBox)

                # Create OK button
                $okButton = New-Object System.Windows.Forms.Button
                $okButton.Text = "OK"
                $okButton.Location = New-Object System.Drawing.Point(120, 140)
                $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $form.Controls.Add($okButton)

                # Show the form and wait for user input
                $result = $form.ShowDialog()

                # Check if the OK button is clicked
                if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                    $ipAddress = $ipTextBox.Text
                    $subnetMask = $subnetTextBox.Text
                    $defaultGateway = $gatewayTextBox.Text

                    # Get the network adapter interface index
                    $interfaceIndex = (Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).InterfaceIndex

                    # Configure the IP settings
                    Set-NetIPAddress -InterfaceIndex $interfaceIndex -IPAddress $ipAddress -PrefixLength $subnetMask -DefaultGateway $defaultGateway
                
                    # Check if the IP settings are configured, if success use the function Show-SuccessMessage
                    if ((Get-NetIPAddress -InterfaceIndex $interfaceIndex).IPAddress -eq $ipAddress -and (Get-NetIPAddress -InterfaceIndex $interfaceIndex).PrefixLength -eq $subnetMask -and (Get-NetIPAddress -InterfaceIndex $interfaceIndex).DefaultGateway -eq $defaultGateway) {
                        Show-SuccessMessage
                    } else {
                        Show-ErrorMessage -message "The IP settings are not configured!"
                    }
                }
                
            }

            "4.2" {

                # Show GUI form to configure DNS servers (1 or 2)
                $form = New-Object System.Windows.Forms.Form
                $form.Text = "DNS Configuration"
                $form.Size = New-Object System.Drawing.Size(300, 200)
                $form.StartPosition = "CenterScreen"
                
                # Create subnet mask label and textbox
                $dns1Label = New-Object System.Windows.Forms.Label
                $dns1Label.Text = "DNS Server 1:"
                $dns1Label.Location = New-Object System.Drawing.Point(20, 20)
                $form.Controls.Add($dns1Label)

                $dns1TextBox = New-Object System.Windows.Forms.TextBox
                $dns1TextBox.Location = New-Object System.Drawing.Point(120, 20)
                $form.Controls.Add($dns1TextBox)

                # Create default gateway label and textbox
                $dns2Label = New-Object System.Windows.Forms.Label
                $dns2Label.Text = "DNS Server 2 (optional):"
                $dns2Label.Location = New-Object System.Drawing.Point(20, 60)
                $form.Controls.Add($dns2Label)

                $dns2TextBox = New-Object System.Windows.Forms.TextBox
                $dns2TextBox.Location = New-Object System.Drawing.Point(120, 60)
                $form.Controls.Add($dns2TextBox)
                
                # Create the button
                $button = New-Object System.Windows.Forms.Button
                $button.Location = New-Object System.Drawing.Point(100, 100)
                $button.Size = New-Object System.Drawing.Size(100, 30)
                $button.Text = "OK"
                $button.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $form.AcceptButton = $button
                $form.Controls.Add($button)

                # Show the form and get the DNS IP address
                $result = $form.ShowDialog()

                if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                    $dnsIP1 = $dns1TextBox.Text.Trim()
                    $dnsIP2 = $dns2TextBox.Text.Trim()

                    # Create an array to store the DNS server addresses
                    $dnsServerAddresses = @($dnsIP1)

                    # Add the second DNS IP address to the array if provided
                    if ($dnsIP2) {
                        $dnsServerAddresses += $dnsIP2
                    }

                    # Set the DNS servers
                    Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).InterfaceIndex -ServerAddresses $dnsServerAddresses    
                
                    # Check if the DNS servers are configured, if success use the function Show-SuccessMessage
                    if ((Get-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).InterfaceIndex).ServerAddresses -eq $dnsServerAddresses) {
                        Show-SuccessMessage
                    } else {
                        Show-ErrorMessage -message "The DNS servers are not configured!"
                    }
                }

            }

            "5.1" {
                $logs = Get-WinEvent -LogName "System", "Application" -MaxEvents 50 |
                    Where-Object {$_.LevelDisplayName -in "Critical", "Error", "Warning"} |
                    Select-Object TimeCreated, LevelDisplayName, LogName, Message

                # If there are no logs, show a message
                if ($logs.Count -eq 0) {
                    Show-ErrorMessage -message "There are no logs!"
                } else {
                    $logs | Out-GridView
                }
            }

            "5.2" {
                $os = Get-WmiObject -Class Win32_OperatingSystem
                $version = $os.Version
                $build = $os.BuildNumber

                # Create a form
                $form = New-Object System.Windows.Forms.Form
                $form.Text = "Version and Build Number"
                $form.Size = New-Object System.Drawing.Size(300, 150)
                $form.StartPosition = "CenterScreen"

                # Create labels for version and build number
                $versionLabel = New-Object System.Windows.Forms.Label
                $versionLabel.Text = "Windows Server Version:"
                $versionLabel.Location = New-Object System.Drawing.Point(20, 20)
                $form.Controls.Add($versionLabel)

                $buildLabel = New-Object System.Windows.Forms.Label
                $buildLabel.Text = "Build Number:"
                $buildLabel.Location = New-Object System.Drawing.Point(20, 60)
                $form.Controls.Add($buildLabel)

                # Create labels to display the version and build number
                $versionDisplayLabel = New-Object System.Windows.Forms.Label
                $versionDisplayLabel.Text = $version
                $versionDisplayLabel.Location = New-Object System.Drawing.Point(150, 20)
                $form.Controls.Add($versionDisplayLabel)

                $buildDisplayLabel = New-Object System.Windows.Forms.Label
                $buildDisplayLabel.Text = $build
                $buildDisplayLabel.Location = New-Object System.Drawing.Point(150, 60)
                $form.Controls.Add($buildDisplayLabel)

                # Show the form
                $form.ShowDialog()
            }

            "6.1" {

                # Create the GUI form for all informations required to create AD accounts
                $form = New-Object System.Windows.Forms.Form
                $form.Text = "AD Accounts Creation"
                $form.Size = New-Object System.Drawing.Size(380, 230)
                $form.StartPosition = "CenterScreen"

                # Create the label for CSV file path
                $csvLabel = New-Object System.Windows.Forms.Label
                $csvLabel.Location = New-Object System.Drawing.Point(10, 20)
                $csvLabel.Size = New-Object System.Drawing.Size(280, 20)
                $csvLabel.Text = "Enter the CSV file path:"
                $form.Controls.Add($csvLabel)

                # Create the textbox for CSV file path
                $csvTextBox = New-Object System.Windows.Forms.TextBox
                $csvTextBox.Location = New-Object System.Drawing.Point(10, 50)
                $csvTextBox.Size = New-Object System.Drawing.Size(280, 20)
                $form.Controls.Add($csvTextBox)

                # Create the label for AD server name
                $adServerLabel = New-Object System.Windows.Forms.Label
                $adServerLabel.Location = New-Object System.Drawing.Point(10, 80)
                $adServerLabel.Size = New-Object System.Drawing.Size(280, 20)
                $adServerLabel.Text = "Enter the AD server name:"
                $form.Controls.Add($adServerLabel)

                # Create the textbox for AD server name
                $adServerTextBox = New-Object System.Windows.Forms.TextBox
                $adServerTextBox.Location = New-Object System.Drawing.Point(10, 110)
                $adServerTextBox.Size = New-Object System.Drawing.Size(280, 20)
                $form.Controls.Add($adServerTextBox)

                # Create the button
                $button = New-Object System.Windows.Forms.Button
                $button.Location = New-Object System.Drawing.Point(100, 140)
                $button.Size = New-Object System.Drawing.Size(100, 30)
                $button.Text = "OK"
                $button.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $form.AcceptButton = $button
                $form.Controls.Add($button)

                # Show the form and get the CSV file path and AD server name
                $result = $form.ShowDialog()

                if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                    $csvFilePath = $csvTextBox.Text.Trim()
                    $adServerName = $adServerTextBox.Text.Trim()

                    # Check if the CSV file exists, if not use the function Show-ErrorMessage
                    if (Test-Path $csvFilePath) {
                        # Import the CSV file
                        $csvFile = Import-Csv -Path $csvFilePath

                        #Prompt for the AD server credentials
                $adServerCredential = Get-Credential

                # Get all OUs
                $ous = Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName

                # Create a form to select the OU in a list
                $form = New-Object System.Windows.Forms.Form
                $form.Text = "OU Selection"
                $form.Size = New-Object System.Drawing.Size(320, 200)

                # Create the label
                $label = New-Object System.Windows.Forms.Label
                $label.Location = New-Object System.Drawing.Point(10, 20)
                $label.Size = New-Object System.Drawing.Size(280, 20)
                $label.Text = "Please select an OU:"
                $form.Controls.Add($label)

                # Create the combobox
                $comboBox = New-Object System.Windows.Forms.ComboBox
                $comboBox.Location = New-Object System.Drawing.Point(10, 50)
                $comboBox.Size = New-Object System.Drawing.Size(280, 20)

                # Add the OUs to the combobox
                foreach ($ou in $ous) {
                    $comboBox.Items.Add($ou)
                }

                $form.Controls.Add($comboBox)

                # Create the button
                $button = New-Object System.Windows.Forms.Button
                $button.Location = New-Object System.Drawing.Point(100, 100)
                $button.Size = New-Object System.Drawing.Size(100, 30)
                $button.Text = "OK"
                $button.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $form.AcceptButton = $button
                $form.Controls.Add($button)

                # Show the form and get the selected OU
                $result = $form.ShowDialog()

                if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                    $selectedOU = $comboBox.SelectedItem.ToString()

                    # Create the AD accounts
                    foreach ($row in $csvFile) {
                        $firstName = $row.FirstName
                        $lastName = $row.LastName
                        $username = $row.Username
                        $password = $row.Password
                        $email = $row.Email

                        New-ADUser -Name "$firstName $lastName" -SamAccountName $username -AccountPassword (ConvertTo-SecureString -AsPlainText $password -Force) -Enabled $true -Server $adServerName -Credential $adServerCredential -EmailAddress $email -Path $selectedOU
                    }

                    Show-SuccessMessage
                }
                    } else {
                        Show-ErrorMessage -message "The CSV file does not exist!"
                    }
                }                
                                
            }
            
    
        }


    } else {
        $continueLoop = $false
    }

    # Dispose the form
    $form.Dispose()
}

$form.Dispose()
