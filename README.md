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

# Cloud Forensics

<ins>**OneDrive**</ins>

- Local Files
  - _%USERPROFILE%\OneDrive_ (default)
    - _NTUSER\Software\Microsoft\OneDrive\Accounts\Personal_ (user folder location)
- Metadata
  - _%AppData%\Local\Microsoft\OneDrive\logs\Personal_ (only id OneDrive enabled)
    - _SyncDiagnostics.log_ provides metadata for local and cloud files
  - _%AppData%\Local\Microsoft\OneDrive\settings\Personal_
    - _\&lt;UserCid\&gt;.dat_ contains a list of local and cloud file names
- Investigative Notes
  - Critical to user registry to determine if enabled
  - Current items in local &amp; cloud storage can be derived, but deleted files are unavailable
  - OneDrive has had many versions and some previously useful logs have be deprecated
- Take Note
  - _LastSignInTime_
  - _UserFolder_
  - _UserEmail_
  - _Cid or UserCid - MS Unique ID for the user tying them to their cloud account_
- OneDrive for Business
  - _NTUSER\Software\Microsfot\OneDrive\Accounts\Business1_
    - _ClientFirstSignInTimestamp_
    - _SPOResourceID: Sharepoint URL for OneDrive instance_
- Tenants
  - Tracks folders sychronized from other sources (other OneDrive accounts)
  - _NTUSER\Software\Microsoft\OneDrive\Accounts\Personal\Tenants_
  - _NTUSER\Software\Microsoft\OneDrive\Accounts\Business1\Tenants_
- SyncEngines
  - _NTUSER\Software\SyncEngines\Providers\OneDrive_
  - Tracks the various items which must be synchronized on the system
    - _MountPoint: Location of files on local file system_
    - _UrlNamespace: Detailed information on source data (SharePoint, OneDrive, etc.)_
    - _LastModifiedTime: Time of the last update to the MountPoint_
- Settings
  - _%AppData%\Local\Microsoft\OneDrive\settings\Personal_
    - _\&lt;UserCid\&gt;.ini_
      - _Library: UserCid and OneDrive folder location_
      - _lastRefreshTime: Last time OneDrive was synchronized with cloud_
      - _requestsSent: Amount of activity during last sync_
      - _BytesTransferred: Amount of data transferred during last sync activity_
    - _\&lt;UserCid\&gt;ProfileServiceResponse.txt_
      - _givenName: First name of user_
      - _Surname: Last name of user_
      - _userPrincipalName: Microsoft cloud account email address_
    - _\&lt;UserCid\&gt;.dat_
      - Show active files in synced folders (local and cloud only)
      - Files Shared with the user
      - Tool: bstrings.exe
        - can show file and folder names
    - _\&lt;UserCid\&gt;.dat.previous_
      - Possibly contains deleted files
- SyncDiagnostic.log
  - _%AppData%\Local\Microsoft\OneDrive\log\Personal_
  - List of folders and file metadata present on hardrive
    - Includes full path, size, creation time, modified time (unix epoch time)
    - Some file and folder names are obfuscated with a key found in a second file
      - ObfuscationStringsMap.txt
    - If logs do not contain Sync Verification data, you will not find file and folder information
      - First List: Local files
      - Second List: Cloud only files

<ins>**OneDrive Business**</ins>

- Local Files
  - _%USERPROFILE%\One Drive - \&lt;Company name\&gt; (default)_
    - _NTUSER\Software\Microsoft\OneDrive\Accounts\Business1_
    - _UserFolder: Location of root OneDrive for Business local storage_
    - _UserName: First and Last name assigned to the account_
    - _UserEmail: Business email tied to Microsoft 365_

- Metadata
  - _%AppData%\Local\Microsoft\OneDrive\logs\Business1_
    - SyncDiagnostics.log provides metadata for local and cloud flies
  - _%AppData%\Local\Microsoft\OneDrive\settings\Business1_
    - \&lt;UserCid\&gt;.dat contains a list of local and cloud file names
- Investigative Notes
  - _\&lt;UserCid\&gt;.dat_ and _SyncDiagnostic.log_ files operate similarly to consumer OneDrive
  - Microsoft 365 Unified Audit Logs give 90 days of detailed usage, including deleted files
- Unified Audit Logs
  - [https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance?view=o365-worldwide](https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance?view=o365-worldwide)
  - Per user, Includes IP address
  - Must be enabled by admin
  - 90 days retention

<ins>**Google Drive**</ins>

- Google Backup and Sync combines Google Drive and Google Photos Uploader into a single application
- Local Files
  - _%USERPROFILE%\Google Drive (default)_
- Metadata
  - _%AppData\Local\Google\Drive\user\_default\_
    - _Sync\_config.db_ provides user info and preferences
      - SQLite database and has useful entries in data table
      - _Local\_sync\_root\_path_: location of locally stored files
      - _User\_email_: google account identifier
      - _Highest\_app\_version_: version of google drive application
    - _Cloud\_graph.db_ contains a complete listing and metadata for local and cloud files (not deleted)
    - _Sync\_log.log_ provides detailed usage on files added, deleted, modified, and renamed (no access)
- Investigative Notes
  - Databases in SQLite format
  - Deleted items available in cloud (online) trash folder and local recycle bin
- Useful fields in the _cloud\_entry_ table _(snapshot.db)_ or _cloud\_graph\_entry_ table _(cloud\_graph.db)_
  - _Filename_
  - _Modified: timestamp begins as the time file was first added to Google Drive, not original file modification time_
  - _Acl\_role: Ownership information. A value of &quot;0&quot; means the Google Drive owner is the file owner_
  - _Doc\_type: Useful to identify folders and differentiate between real files and google documents_
    - _0 = Folder_
    - _1 - Regular File_
    - _2-13+ = Different types of google files/objects_
  - _Size_
  - _Checksum: MD5 hash of the file contents_
  - _Shared: indicates whether the file is currently marked as shared. A value of &quot;0&quot; is not shared. 1 = shared._
- _Sync\_log.log_
  - Action.CREATE: File added to google drive
  - Action.DELETE: File deleted from google drive
  - Action.MODIFY: File updated
  - Action.RENAME: File renamed
  - Action.CHANGE\_ACL: Attribute changed on file
  - Action.MOVE: File moved to a different google drive folder
  - Direction.UPLOAD: activity occuring that updated the local copy of files
  - Direction.DOWNLOAD: change made via the local filesystem that must be sycnhronized

<ins>**Google Workspace File Stream**</ins>

- Provides features of Backup and Sync, with addition of &quot;files on demand&quot;
- Local Files
  - Virtual FAT32 Volume
  - The folder &quot;My Drive&quot; contains the synchronized files
  - _NTUSER\Software\Google\DriveFS\Share_ tracks the local drive letter used
  - Cached Files
    - _%AppData%\Local\Google\DriveFS\\&lt;account identifier\&gt;\content\_cache_
- Metadata
  - _%AppData%\Local\Google\DriveFS\\&lt;account identifier\&gt;_
    - _Metadata\_sqlite\_db_ contains a list of offline, cloud only, and deleted files present
- Investigative Notes
  - Much fewer filesystem artifacts
    - Due to virtual memory used, files will not be present on the filesystem (but may be cached)
  - Usage activity is available via Google Admin Report (180 days of activity)
- Metadata\_sqlite\_db
  - %AppData%\Local\Google\DriveFS\\&lt;base64 encode of user account email\&gt;
  - Table: items
    - Stable\_id: file identifier
    - Id: used to cross reference files in the Google Workspace Drive audit reports
    - Trashed: Is the file deleted (in trash folder)
    - Is\_owner: is the authenticated user the owner of this file
    - Is\_folder: doe the entry refer to a file or folder
    - Local\_title: Name of file or folder
    - File\_size
    - Modified\_date: timestamp begins when file is first added to Google Drive
    - Viewed\_by\_me\_date: time of last user interaction
    - Shared\_with\_me\_date: time a shared file was added to the drive
  - Table: item\_properties
    - Pinned: has the file been set to be stored offline
    - Local-title: name of file or folder
    - Local-content- modified-date: modification time of the file reported from the local filesystem
    - Drivefs.Zone.Identifier: Browser Zone.Identifier data
    - Trashed-locally: was the file deleted on the filesystem as opposed to the cloud
    - Trashed-locally-name: the name of the deleted file as it exists
    - Content-entry: property is present when a file is locally cached
- Cache
  - File stream keeps a local cache of files in the _content\_cache folder_
  - _Item\_properties_ table in _metadata\_sqlite\_db_ can point to name and files sizes
    - _Content-entry_ property cache
  - Cached files are renamed but can be identified by
    - File Size
    - Header Analysis
    - Hash (if available)
- Logging
  - CSV export via API
  - Alerts can be set up on any combination of files

<ins>**Dropbox**</ins>

- Local Files
  - _%USERPROFILE%\DropBox (default)_
  - _%USERPROFILE%\Dropbox\.dropbox.cache (temporary files only)_
- Metadata
  - _%AppData%\Local\Dropbox\_
    - _Filecache.dbx_ contains a complete listing and metadata for local, cloud, and deleted files
      - \*\*Note: This database is not likely to be found after Dropbox version 90\*\*
- Investigative Notes
  - Configuration files info.json and config.dbx provide application details
  - Dropbox databases are SQLite, but encrypted using Windows DPAPI
    - Live acquisition or knowledge of user credentials is critical
  - No local usage logging (available online)
- _Info.json_
  - _Path: local path for synchronized files_
  - _Is\_team: Is this account part of a dropbox team, having access to team files?_
  - _Subscription\_type: Tier of service_
- _Host.db_
  - Contains the dropbox file path (base64 encoded)
- DropBox DBX decryption - decwindbx
  - Open source DPAPI toolkit for DropBox databases
    - Decrypts _filecache.dbx_ and _config.dbx_
    - Offline Requirements: NTUSER.DAT, &quot;Protect&quot; folder, user password (or SHA1)
    - [http://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](http://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
    - [https://github.com/dfirfpi/decwindbx](https://github.com/dfirfpi/decwindbx)
  - Keys are stored
    - NTUSER\Software\Dropbox\ks\Client
    - NTUSER\Software\Dropbox\ks1\Client
    - Extract with dbx-key-win-live.ps1
    - Offline images
      - _%USERPROFILE%\AppData\Roaming\Microsoft\Protect_
      - NTUSER.DAT
      - User&#39;s Password (Only requires SHA1 hash)
        - Extract from RAM
        - Cracked from the SAM Registry hive
    - Next run key-win-dpapi.py to decrypt DropBox keys
    - Finally run, sqlite-dbx-win64.exe to decrypt the _filecache.dbx_ database
- _Config.dbx_
  - Contains application configuration data
    - Username, email, team, local storage size, hostname, etc.
- Filecache.dbx
  - Provides file metadata
    - File\_journal: metadata for localm remote, and deleted files
    - Deleted\_fileids includes full path of all deleted files and deletion times
    - File\_journal\_fileid: provides number of versions available for each file
- Logging
  - On by default - Only Advanced+ tier
  - CSV export via &quot;Create report&quot;



<ins>**Box**</ins>

- Local Files
  - _%USERPROFILE%\Box (default) - reparse point pointing to virtual system_
  - _%AppData%\Local\Box\Box\cache_
- Metadata
  - _%AppData%\Local\Box\Box\logs_
  - _%AppData%\Local\Box\Box\data (Databases)_
- Investigation Notes
  - _Box\_streem_ logs provide detailed usage of information, including files added, updated, removed, and opened
    - logDriveInformation: location of folder
    - File format: box\_streem\_#\_\&lt;date\&gt;.log

- _Sync.db &amp; streemsfs.db_ databases provide filename, file size, timestamps, access time, and SHA1 hashes for offline and online files
  - _Box\_item_ table
    - Filename, parent, SHA1 hash, file size, created &amp; last modified
  - _Local\_item_ table
    - Inode: Universal ID assigned to file which can be useful for quickly matching with other databases like _streemsfs.db_
- _Metrics.db_ provides Box user account information (email login)
  - Aggregated\_metrics table: provides user, or email login used to authenticate Box servers
- _Streemsfs.db_
  - Tracks items that have been locally cached on the filesystem (marked for offline use) or accessed from the cloud (and subsequently saved locally)
  - Deleted items database: _%AppData%\Local\Box\Box\data_
  - _Fsnodes_ table:
    - _Name: original file name_
    - _CreatedatTimestamp: Creation of file (Unix Epoch Time)_
    - _ModifiedatTimestamp: :Last Modification time of file (Unix Epoch Time)_
    - _AccessedatTimestamp: last accessed time of the file (when file was added to Box or when file was last opened from local Box folder - Unix Epoch time)_
    - _inodeId: Identifier used to determine parent folders and as foreign key in cachefiles table_
    - _parentInodeId: InodeId for parent folder_
    - _MarkforOffline: Folders that have been selected by the user to keep persistent offline local copies (only folders can be set to offline status)_
    - _folderFetchTimestamp: when folder content was last synchronized with cloud_
  - _Cachfiles_ table
    - _cacheDataId: Filename within the Box cache folder of the locally saved file_
    - _Size: File size of cached files (in bytes)_
    - _inodeID: Identifier used as foreign key in fsnodes table_
    - _Age: Time file was cached; a &quot;0&quot; value means not yet cached (unix epoch time)_

<ins>**Box Backup and Sync Application**</ins>

- Local Files
  - %USERPROFILE%\Box Sync (default - NOT a virtual folder like Box Drive)
  - All synced files are persistent in the local filesystem
- Metadata
  - %AppData%\Local\Box Sync
    - Sync.db contains user information, filenames, parent folder, file size, and SHA1 hash of both current and deleted /unsynced files
  - %AppData\Local\Box Sync\Logs
- Investigative Notes
  - Box Sync-\&lt;Version\&gt;.log records creates, deletes, and changes to synced files
    - Logs can be large, recording approximately one month of activity
    - Includes LOGIN\_NAME and LAST\_SYNCED\_TIME
  - Sync.db
    - Preferences table
      - User\_id: Unique user identifier
      - Login\_name: Email address of authenticated user
      - Sync\_directory\_path: Location of the Box Sync file folder
      - Last synced time: Time of last synchronization activity
      - Last\_attempted\_update\_version: version of Box application
    - Box\_item table
      - Box\_id: Numeric identifier for file in cloud storage
      - Name: file name
      - Parent\_item\_id: parent folder (box\_id)
      - Size: file size
      - Checksum: SHA1 hash of currently synced and deleted files
      - Is\_deleted: records a value of &quot;1&quot; if a file is no longer on the local files system
  - Monitor\_state.db
    - Box\_scanned\_item table
      - Sequence\_id: identifies how many saved version updates Box has saved for each file (0=original version)
      - Is\_deleted: The field is present, but does not appear to be used in this database
