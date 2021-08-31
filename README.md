# Registry Overview

<ins>**System Registry Hives**</ins>

- *%WinDIr%\\System32\\Config*
    
    - SAM
        
    - Info about user accounts
        
    - Password last changed
        
    - Last logon
        
    - In user accounts
        
- Security
    
    - Access Control list
        
    - Stored passwords
        
- System
    
    - Configuration data (hardware)
- Software
    
    - Configuration data (software/os)
- Default
    
    - Not much of use

<ins>**User Registry Hives**</ins>

- *%UserProfile%*
    - NTUSER.DAT
    - Most recently used files
    - Last files searched for
    - Last typed URLs
    - Last commands executed
    - Opened Files
    - Last Saved DIles
- *%UserProfile%\\AppData\\Local\\Microsoft\\Windows*
    - USRCLASS.DAT
    - Program Execution
    - Opened and closed folders
    - Aids User Account Control (UAC)
    - HKCU\\Software\\Classes
- *%WinDir%\\appcompat\\Programs*
    - AMCACHE.hve
    - Excecution data

# Users & Groups

- *SAM\\Domains\\Account\\Users*
    
- Username
    
- Relative Identifier
    
- User Login Information
    
    - Last Login
        
    - Last Failed Login
        
    - Logon Count
        
    - Password Policy
        
    - Account Creation Time
        
- Group Information
    
    - Administrators
        
    - Users
        
    - Remote Desktop Users
        

# System Configuration

<ins>**Identify Current Control Set**</ins>

- *SYSTEM\\Select*
- Systems Configuration Settings
- Identify what ControlSet is in use

<ins>**Identify Microsoft OS Version**</ins>

- MS Windows Version
    
    - *ProductName*
        
    - *ReleaseID* (YYMM)
        
- Service Pack Level
    
- Install Date of the last version/major update
    
    - *InstallDate*
- *SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion*
    

<ins>**Computer Name**</ins>

- *SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName*
- Name linked to log files, network connections
- Verify the PC that is being examined

<ins>**Time Zone of the Machine**</ins>

- *System\\CurrentControlSet\\Control\\TimeZoneInformation*
- Correlation Activity
- Log Files\\TimeStamps

<ins>**Network Interfaces**</ins>

- *SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces*
- Static or DHCP
- Ties machines to network activity
- Interface GUID for additional profiling

<ins>**Historical Networks**</ins>

- SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed
- *SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged*
- *SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Nla\\Cache*
- Identify Networks Computer has been connected to
- Could be wired or wireless
- Domain/intranet Name
- Identify SSID
- Identify Gateway MAC Address
- First and Last Time network connection was made
- Networks that have been connected to via VPN
- MAC address of SSID for Gateway can be physically triangulated
- Write Down ProfileGUID

<ins>**Network Types**</ins>

- *SOFTWARE\\Microsoft\\WZCSVC\\Parameters\\Interfaces\\{GUID}* (XP)
    
- *SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles* (Win7-10)
    
- ID the type of network that the computer connected to
    
- ID wireless SSIDs that the computer previously connected to
    
    - *ProfileName*
- Time is recorded in LOCAL TIME, NOT UTC
    
- First and Last Connection Time
    
    - *DateCreated*
        
    - *DateLastConnected*
        
- Determine Type using Nametype
    
    - *6 (0x06) = Wired*
        
    - *23 (0x17) = VPN*
        
    - *71 (0x47) = Wireless*
        
    - *243 (0xF3) = Mobile Broadband*
        
- Network Category
    
    - *(Public) 0 - Sharing Disabled*
        
    - *(Private) 1 - Home, Sharing Enabled*
        
    - *(Domain) 2 - Work, Sharing Enabled*
        
- Geolocate
    
    - [Wigle.net](/C:/Program%20Files/Joplin/resources/app.asar/Wigle.net)

<ins>**System AutoStart Programs**</ins>

- Programs exhibiting persistence
    
    - User login
        
    - Boot time
        
- *NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*
    
- *NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce*
    
- *Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce*
    
- *Software\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\Run*
    
- *Software\\Microsoft\\Windows\\CurrentVersion\\Run*
    
- *(Services) SYSTEM\\CurrentControlSet\\Services*
    
- IF start set to 0x02, then service application will start at boot (0x00 for drivers)(
    
- Determine programs that start automatically
    
- Useful for finding malware on a machine that installs on boot such as a rootkit
    
- Look at when the time key was last updated; generally last boot time of the system
    

<ins>**Last Shutdown Time**</ins>

- Discover when the system was last shutdown
- How many successful times the system was shutdown
- *SYSTEM\\CurrentControlSet\\Control\\Windows (Shutdown Time)*
- *SYSTEM\\CurrentControlSet\\Control\\Watchdog\\Display (Shutdown Count) - XP only*
- Detect certain types of activity
- Determine if the user properly shuts down their machine

# User Activity

<ins>**File Search History**</ins>

- *NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery*

<ins>**Typed Paths**</ins>

- *NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths*

<ins>**Recent Docs**</ins>

- *NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs*

<ins>**Microsoft Office File**</ins>

- *NTUSER.DAT\\Software\\Microsoft\\Office\\&lt;Version&gt;*
    
    - 15.0 - Office2013
        
    - 11.00 - Office 2003
        
    - 14.00 - Office 2010
        
    - 10.0 - Office XP
        
    - 12.0 - Office 2007
        
- *NTUSER.DAT\\Software\\Microsoft\\Office\\VERSION\\&lt;APPNAME&gt;\\User MRU\\LiveID_####\\File MRU*
    
    - 16.0 - Office 2016\\2019\\M365

<ins>**Reading Locations**</ins>

- *NTUSER.DAT\\Software\\Microsoft\\Office\\&lt;VERSION&gt;\\&lt;APPNAME&gt;Reading Locations*

<ins>**Common Dialog Box**</ins>

- *LastVisitedMRU*
    
    - Last path of file opened
        
    - Executable used
        
    - \*NTUSER.DAT\\Software\\Microsoft\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedpidlMRU\*
        
- *OpenSaveMRU*
    
    - Save or open dialog box
        
    - Last files opened by a specific extension
        
    - \*NTUSER.DAT\\Software\\Microsoft\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavepidlMRU\*
        

# Application Execution

**<ins>Background/Desktop Activity Moderator</ins>**

- Background Activity Moderator (BAM)
- Desktop Activity Moderator (DAM)
- Utilized for "Connected Standby" application throttling to save battery power
- *SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings\\{SID}*
- *SYSTEM\\CurrentControlSet\\Services\\dam\\UserSettings\\{SID}*
- Win 10 Only
- Provides full path of executable file
- Last execution date

<ins>**Last Command Executed**</ins>

- MRUList
    
- Order in which commands were executed
    
- Commands
    
    - XP/Vista/Win7/8 commands typed into the RUN box
        
    - Invoked typically through the WINDOWS+R keys
        
- *NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU*
    

**<ins>GUI Program Execution: UserAssist Key</ins>**

- *NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}\\Count*
    
    - Information for each GUI program launched in Window's Explorer
        
    - Last Run Time (UTC)
        
    - Run Count
        
    - Name of GUI Application
        
    - Focus Time: Total time an application has focus, expressed in milliseconds
        
    - Focus Count: Total number of times an application was re-focused in Explorer (mouse moved over application and clicked)
        
- UserAssist GUIDs
    
    - https://docs.microsoft.com/en-us/dotnet/desktop/winforms/controls/known-folder-guids-for-file-dialog-custom-places?view=netframeworkdesktop-4.8&redirectedfrom=MSDN

<ins>**Prefetch & Superfetch**</ins>

- *C:\\Windows\\prefetch*
    
- Utilized to show application execution (what and when)
    
- (exename) - (hash).pf
    
- Compressed
    
- Hash calculated based on &lt;dir&gt; path of executable and the command line options of certain programs (e.g., svchost.exe)
    
- *C:\\windows\\prefetch\\Layout.ini*
    
    - Contains original path names of the files located in the prefetch
- Located within prefetch file
    
    - Number of times executed
        
    - Original path
        
    - Last time of execution
        
- Date Created: First Executed (subtract 10 sec)
    
- Date Modified: Last Executed (subtract 10 sec)
    
- PECmd.exe
    
    - PECmd.exe -f (single parsing)
        
    - PEcmd.exe -d (directory parsing)
        
    - -k allows you to supply a comma-separated list of values you want to highlight
        
    - "Run From" directory highlighted
        
    - *PECmd.exe -d "C:\\Windows\\prefetch" --csv "E:\\" -q*
        
- Device Profling
    
    - Map device name to mount point
        
        - EventID 98 in System Logs
            
        - Volume Device Name: event logs, prefetch
            
        - Volume Serial Number: prefetch, LNK/jumplist
            
        - Volume Creation Time: prefetch
            
        - Volume Name: event logs, LNK/jumplist
            
        - Volume Mount Point: event logs, LNK/jumplist
            
        - Times of Use: prefetch, LNK/jumplist
            
        - Files and Folders Present: LNK/jumplist
            
- Superfetch
    
    - Designed to anticipate frequently run applications after system activity like standby mode, hibernation, and fast user switching
        
        - Executable names
            
        - Execution count
            
        - Foreground count
            
        - Supporting files (dlls, zips, database files)
            
        - Full path information
            
        - Timeframes
            
        - Timestamps
            
- Tools: Superfetchlist.exe
