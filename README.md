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

# Cloud Storage

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

<ins>**Device Synchronization Timestamps**</ins>

- Modification time are preserved in all apps ( :star: = preserved)
    - Folder modification time updated to reflect new files in folder



| **Application** | **Modification Time** | **Creation Time** | **Access Time** |
| :-------------: | :-------------------: | :---------------: | :-------------: |
| OneDrive | :star:   | Time of Sync | Time of Sync |
| OneDrive Business | :star:   | Time of Sync | Time of Sync |
| Google Drive | :star:   | Time of Sync | Time of Sync |
| Google File Stream | :star:   | :star:   | :star:  |
| Dropbox | :star:  | Time of Sync | Time of Sync |
| Box Drive | :star:   | Time of Sync | Modification Time |
| Box Backup & Sync | :star:   | :star:  | Time of Sync |

<ins>**Forensic Challenges**</ins>

- Many cloud drive apps are implemented as &quot;on-demand&quot;
  - Offline copies of files may not be present or difficult to access
  - Access to drive folder is only possible on live, logged on system
  - Raw contents in the cloud may be encrypted
- Case Study: Box Drive
  - Box folder is an NTFS reparse point to a virtual filesystem
  - A forensic image of the C drive only captures the reparse tag
- Solution(s)
  - Logical imaging of drive folders (requires user to be logged in)
  - Collect data using cloud API (requires user credentials)

<ins>**Kape Targets for Cloud Storage**</ins>

- Kape can collect cloud metadata and files (including &quot;on-demand&quot;)
- Targets
  - CloudStorage.tkape (OneDrive, Google Drive, Dropbox, Box)

<ins>**Cloud Storage API collection**</ins>

- Google Takeout/Workspace Export
  - [https://takeout.google.com](https://takeout.google.com/)
- F-Response
  - OneDrive
  - G Drive
  - Workspace
  - Dropbox
  - Box
- Magnet Axiom
  - OneDrive
  - G Drive
  - Workspace
  - Dropbox
  - Box
  - iCloud

<ins>**Cloud Storage Identification via Browser Artifacts**</ins>

- URL Parameters
- Page Title
- Can Provide
  - File Sharing
  - Access to Deleted items
  - File version history
  - Files and folder accessed
  - Searches conducted by the user

<ins>**Cloud Storage Identification via OS Artifacts**</ins>

- Shadow Copies
- Lnk files and Jumplists
- Registry &quot;files opened&quot;
  - RecentDocs
  - Office FileMRU
  - OpenSavePidlMRU
- Shellbags
- Directory Indexes
- IE file history
- Prefetch
- Recycle Bin
- Memory Analysis (cached files)


<ins>**Cloud Storage Forensic Summary**</ins>

- Metadata (Local)
    - Local files present and associated metadata
- Metadata (Cloud)
    - Files present in a user's cloud storage that are not currently synchronized to the local system
- File Hashes
- Deleted Items (db)
    - Deleted items referenced within locally stored databases
- Cached Files
    - Can include cloud-only or deleted items not regularly present on the filesystem
- Usage Logs
- Virtual Filesystem
    - Ensure the contents of the local storage folders are captured (requires credentials or live, logged-in system)

| **Application** | **Metadata**<br>**(Local)** | **Metadata**<br>**(Cloud)** | **File Hashes** | **Deleted Items (db)** | **Cached Files** | **Usage Logs** | **Virtual File System** |
| :---------------: | :---------------: | :---------------: | :---------------: | :---------------: | :---------------: | :---------------: | :---------------: |
| OneDrive | ⭐   | ⭐   |     |     |     |     |     |
| OneDrive Business | ⭐   | ⭐   |     |     |     | ⭐   |     |
| Google Drive | ⭐   | ⭐   | ⭐   |     |     | ⭐   |     |
| Google File Stream | ⭐   | ⭐   |     | ⭐   | ⭐   | ⭐   | ⭐   |
| Dropbox | ⭐   | ⭐   |     | ⭐   |     | ⭐   |     |
| Box Drive | ⭐   | ⭐   | ⭐   |     | ⭐   | ⭐   | ⭐   |
| Box Backup & Sync | ⭐   |     | ⭐   | ⭐   |     | ⭐   |     |

# Shell Items


<ins>**Shell Items Overview**</ins>

- Data or a file that has information to access another file is known as a Shell Item
- Shell Item Artifact Attributes
  - Type of Drive Target is On
    - Fixed, Removable, Network
  - Path of Target File
    - Drive Letter, Volume Label, Volume Serial for Locally Attached
    - Server Share Path or Drive Letter (optional) for network
    - If the target is in a "special" or "known" folder
  - Target Metadata
    - MAC Timestamps
    - Size
    - MFT Record
    - Sequence Number


<ins>**Shell Item Structure**</ins>

- *Header*
  - CLSID (sig.)
  - Attributes
  - Timestamps
  - Size
  - What other sections of the LNK file exist
- *PIDL*
  - After *Header*
  - Contains a shell path to the target file
- *LinkInfo* Section
  - After *PIDL*
  - Describes the path
  - Drive Type
  - Serial #
  - Volume Label
  - Path
- *StringData*
  - After *Link Info*
  - Contains up to 5 strings
  - Name
  - Relative Path
  - Working Dir
  - Command Line Arguments
  - Icon Locations
- *CNRL*
  - Inside *LinkInfo*
  - Share Path
  - Device Name/Letter
- *ExtraData*
  - After *StringData*
  - *Property Store* data block
    - Contains arbitrary information, and the *TrackerInformation* data block which can be used to track files across multiple Windows systems


<ins>**Shortcut Files (.lnk)**</ins>

- Automatically created by Windows in Recent Folder
- Win7 - Win10
  - *C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent*
- Any non-executable opened in Windows generates TWO LNK files
  - 1: Target File
  - 2: Parent folder of target file
  - Max = 149 file and folder LNK files in the *Recent* directory
- Shortcut (.lnk) files will point to:
  - Target file MAC times
  - Volume information (Name, Type, Vol. Serial Number)
  - Fixed, removable, or network target
  - Original path and location
- Time of First/Last Open
  - First Opened
    - Creation Date of shortcut file
  - Last Opened
    - Modification date of shortcut file
- File Changes in Win 10
  - File Creation
    - LNK file of Folder and File
  - Folder Creation
    - LNK file of
      - Folder
      - Parent Folder
      - Grandparent Folder
  - LNK File Types
    - 20 per extension
    - 30 for folder references
    - 149 in total
- LECMD.exe
  - LNK Explorer Command Line edition
    - Source timestamps - From LNK file
    - Target timestamps - From where the file is located
    - Flags in the header determine what other structures are available in the lnk file
- URL LNK Files
  - Evidence of accessing website from:
    - Run Dialog
    - Windows Search
    - Link in an Application (Slack, Skype, OneNote)


<ins>**Jumplists**</ins>

- Provides another location to verify the opening and/or creation of non-executable files
- Records file access for a specific application
- Can help discern that a wiped/deleted file at one point existed inside the filesystem
- Includes full path
- Destinations (nouns)
  - Pinned Category
  - Known Categories
  - Custom Categories
- Tasks (verbs) 
  - User Tasks
  - Taskbar Tasks
- Types
  - Automatic - created for each app by Windows
  - Custom - created with specific development information for the app developer
- Automatic Destinations
  - *C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations*
  - Sorted by AppID
  - Creation Time = First time item added to the AppID files. First time of execution of application, with the file open
  - Modification Time = Last time item added to the AppID file. Last time of execution of application, with file open
- Custom Destinations
  - *C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations*
  - Creation Time = First time item added to the AppID files. Typically corresponds to the first time of execution of application
  - Modification Time = Last time item added to the AppID file.
  - Must be carved for LNK files or manually extracted using a hex editor (difficult)
- AppIDs
  - <https://forensicswiki.xyz/wiki/index.php?title=List_of_Jump_List_IDs>
  - Many Automatic Destinations match a Custom Destination AppID
- Structured Storage Viewer
  - Left Column = Streams
    - Separate LNK file
    - Numerically ordered from the earliest one (usually 1) to the most recent
  - Right Click the stream for options to save data
- JLECmd.exe
  - Decodes information contained in custom and automatic destination jumplists
  - --dumpTo allows for the exporting of LNK files to a directory
  - Best practice use "--csv" and -q options
  - LastModified - Time entry added
  - EntryNumber - List of Entries
  - LastUsedEntry - Last added


<ins>**Shellbags**</ins>

- Contains user-specific Windows OS folder and viewing preferences to Windows Explorer
- Location
  - Explorer Access
    - USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags
    - USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
    - USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\ShellNoRoam\BagMRU
    - USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\ShellNoRoam\Bags
  - Desktop Access
    - NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
    - NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags
    - NTUSER.DAT\Software\Microsoft\Windows\ShelNoRoam\Bags
    - NTUSER.DAT\Software\Microsoft\Windows\ShellNoRoam\BagMRU

- Investigative Notes
  - Show which folders were accessed on the local machine, network, and/or removeable devices
  - Evidence of previously existing folders after deletion/overwrite
  - When certain folder were interacted with
- BagMRU
  - 0 = My Computer
    - Subkeys = Drives
  - 1 = Drive
    - Subkey = Folders
- Contain MAC times of folders
- Ref: <https://www.sciencedirect.com/science/article/pii/S1742287609000413>
- MRUListEx Indicator
  - Directory was interacted with at that time (Last Key WriteTime)
  - All other timestamps within a tree are reset to that timestamp
- Differentiate Drives
  - File record number (inode number) and sequence number allow you to separate drives
  - FAT32 = Sequence number null
  - NTFS = Sequence number exists
  - Match a returned device to directories accessed to make sure you are looking at the right device
- ShellBagsExplorer.exe
  - Absolute Path - Folder Name
  - ShellType
  - NTFS MFT Entry
  - NTFS Sequence Number - If null the its not NTFS
  - FirstExplored - Folder First Interacted Time
  - Last Explored - Folder Last Interacted Time (MRUListEx)

# USB Analysis

**USB Overview**

- Removable Device Information
  - Vendor/Make/Version
  - Unique Serial Number
- User Information and Activity with USB Device
  - Determine Drive Letter Device and Volume Name
  - Find User That Used the Specific USB Device
  - Discover First Time Device Connected
  - Determine Last Time Device Connected
  - Determine Time Device Removed
- Device Types Mounts as Hard Disk Drive

  - Physical access to the underlying filesystem
  - Ex: External Drives, Thumb/Flash Drives, and MP3 Players

  - Picture Transfer Protocol (PTP)
    - No access to the underlying filesystem
    - Copy media from, not to a connected device
    - Only images and video files
    - XP - Mounts as Windows Image Acquisition (WIA)
    - Win7-10 - Mounts as Portable Devices
  - Media Transfer Protocol (MTP)
    - No access to the underlying filesystem
    - Access to internal SD card
    - Copy files to/from connected device
    - Any file type
    - Win7 - Mounts as portable devices
    - Ex: MP3, cameras, smartphones, tablets

**Evidence of File Opening**

- MSC Devices
  - Created LNK files for all the files that were opened
    - Windows Recent Folder
    - Microsoft Office Recent Folder
    - Jumplist Automatic Destinations
- MTP Devices
  - May or may not create LNK files (depends : app | filetype)
  - Some MTP LNK files do not point back to the MTP source device but instead to the WPDNSE folder on Win7/8 only
    - C:\Users\\&lt;user\&gt;\AppData\Local\Temp\WPDNSE\{GUID}
    - Maintains a copy of the file that was opened from the device
    - Folder does not survive reboot
- Discover Volume Name
  - Discover the Volume Name of the device when it was plugged into the machine
  - _SOFTWARE\Microsoft\Windows Portable Devices\Devices_
  - Identify the USB device that was last mapped to a specific Volume Name using USB unique Serial Number of the USB device (Win 7 only)
  - Find Serial Number via USBSTOR
  - Volume Name can be mapped to drive letter via examination of LNK files
  - Key is not cleaned as part of the Plug and Play Cleanup scheduled task and retains more historical removeable device information
  - Has 30 day limit

**USB MSC Device Forensic Process**

1. Determine Vendor, Product, Version, Serial Number

  1. _SYSTEM\CurrentControlSet\Enum\USBSTOR_

    1. **Vendor =**
    2. **Product =**
    3. **Version =**
    4. **USB Unique Serial Number =**

1. Determine Vendor-ID (VID) and Product-ID (PID)

  1. _SYSTEM\CurrentControlSet\Enum\USB -\&gt; Perform search for USB S/N_

    1. **VID\_XXXX = (Vendor ID)**
    2. **PID\_YYYY = (Product ID)**

    1. Ref: [http://www.linux-usb.org/usb.ids](http://www.linux-usb.org/usb.ids)

1. Determine Last Device Drive Letter and Volume GUID

  1. _SYSTEM\MountedDevices_ - \&gt; Search for Serial in Values

    1. **Drive Letter =**
    2. **Volume GUID = (note without the brackets)**
  1. Small amounts of data = Hard Drives

1. Determine Volume Name

  1. SOFTWARE\Microsoft\Windows Portable Devices\Devices - \&gt; Perform Search for USB Serial Number and Match with Volume Name

    1. **Volume Name =**

1. Find User That Used the Specific USB Device

  1. _NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2_ -\&gt; Search for Volume GUID

    1. **User =**

1. Also tracks mapped shares (often seen intrusions)

  1. Compromised accounts
  2. Lateral Movement

1. Determine First time Device Connected

  1. _C:\Windows\inf\setupapi.dev.lo_g -\&gt; Perform search for USB Unique Serial Number

    1. **Time/TimeZone =**

1. _SYSTEM\CurrentControlSet\Enum\USBSTOR\\&lt;Ven\_Prod\_Version\&gt;\\&lt;USB iSerial #\&gt;\Properties\ {83da6326-97ab-4088-9453-a1923f57b29}\0064_ -\&gt; Value = Windows 64-Bit Hex Value timestamp - Use Dcode Date

  1. **First Time Device Connected =**

1. Determine Last Time Device Connected

  1. _SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven\_Prod\_Version\USB iSerial #\Properties\ {83da6326-97ab-4088-9453-a1923f57b29}\0066_-\&gt; Value = Windows 64-Bit Hex Value timestamp - Use Dcode Date

    1. **Last Time Device Connected =**

1. Determine Time Device Removed

  1. SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven\_Prod\_Version\USB iSerial #\Properties\ {83da6326-97ab-4088-9453-a1923f57b29}\0067 -\&gt; Value = Windows 64-Bit Hex Value timestamp - Use Dcode Date

    1. **Time Device Removed =**

**Removable Devices Event Logs**

- Scenario
  - Determine what hardware devices have been installed on the system
- Relevant Event Ids
  - 20001 - Plug and Play driver install attempted (System log)
  - 4663 - Attempt to access removable storage object (Security log)
  - 4656 - Failure to access removable storage object (Security log)
  - 6416 - A new external device was recognized on system (Security log)
- Investigative Notes
  - System log identifies device type and Serial Number but shows only first time a device has been plugged in
  - Security log can identify every time a device is accessed and what files and folders were accessed

**Tracking Removable Devices in System Log**

- Event ID 20001
- Timestamp: The time and date that the device driver installation was attempted
- Device Information: Embedded device information captured by the Plug and Play manager
- Device Serial Number
- Status: error code associated with the device installation (0x00 = no errors)
- Microsoft-Windows-DriverFramworks-UserMode/Operational
  - Provides similar logs
  - Require enablement

**Audit Removable Storage**

- Logs every interaction with a removeable device by user
- Includes folder, filenames, and application used
- Successful and failed attempts
  - 4663/4656
- Does not provide hardware details (only volume number)

**Audit Plug and Play Activity**

- Logs every time Plug and Play detects a device
  - Only successful events


# Email Forensics

**Email Forensics Overview**

- Who sent the email
  - Email address
  - IP address
  - Contextual clues
- When was it sent
  - Header date and time
  - Mail server timestamps
- Where was it sent from
  - IP address/ISP
  - Geolocation
  - Mail server domain
  - Message-ID
- Is there relevant content
  - Message body
  - Attachments
  - Address book
  - Calendar entries

**Email Headers**

- Received From
  - Bottom-most entry (the originating mail server)
  - Each Mail Transfer Agent (MTA) adds a received entry
  - Entries include
    - Server IP
    - Server Name
    - Date/Time/Time Zone
- Message ID
  - Provided by the originating mail server
  - Unique identifier appended to the server name with an &quot;@&quot; symbol
  - Tracking number for the message
- X-Mailer
  - Identifies the email client used to create the email message

- X-Originating-IP
  - Identifies the IP address of the computer used to send the original message
  - Can be forged (requires control on the originating MTA)
  - If not present, it may still be recorded in the &quot;Received&quot; field
  - Also X-IP
  - X-Forwarded-For
    - Indicates the email was forwarded from another source (sometimes included originating IP)

**Email Authenticity**

- Sender Policy Framework (SPF)
  - Validates the sending IP address to the originating domain
- DomainKeys Identified Mail (DKIM)
  - Verifies the message content has not changed via digital signature
- Domain-based Message Authentication (DMARC)
  - Allows senders to set a policy of what should be don&#39;t if SPF and DKIM checks fail can authenticate the &quot;header from&quot; address with SPF/DKIM information

**Messaged-ID Threading**

- References
  - Simple list of message-IDs for each proceeding messages in the thread
  - Can be used to reconstruct threads

**Extended MAPI Headers**

- Microsoft messaging architecture
  - Core component of Exchange and Outlook
  - Significantly increases email header properties
  - Additional timestamps
    - Mapi-Client-Submit-Time (time on local system when the email was submitted by the email client)
    - Pr\_Creation\_Time (creation of the email)
    - Pr\_Last\_Modification\_Time (compare with creation time, can show the message was manipulated)
    - Mapi-Conversation-Index (times of other messages in thread)
  - Additional Unique Identifiers
    - Mapi-EntryID
  - Information on actions taken on message
    - Mapi-Message-Flags (When an email is saved or send, identify when messages are opened from multiple .PST files)
    - Pr\_Last\_Verb\_Executed (read, replied, forwarded, etc.)
    - Pr\_Last\_Verb\_Executed\_Time
  - Tools
    - Outlook Spy
    - Outlook Redemption
    - MetaDiver

**Host Based Mail Overview**

- Identify all email storage locations
  - Find via filetype searches
  - Review email client configuration info
  - Search for index and message files
- Potential for password protection
- Search for deleted email archives
- Outlook
  - Extension: .PST
  - Archived stored by default in:
    - %USERPROFILE%\Documents\Outlook
  - Registry key tells what archives are being used:
    - HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook
  - Encryption/obfuscation enabled by default
  - Archive size can be set up to 50 GB
  - Typically used for backups or email archives today
- Offline Outlook Data File (.OST)
  - Dominant format for Microsoft email
    - &quot;Cached Exchange Mode&quot;
    - M365, Exchange, Outlook.com, IMAP
  - Stored on local system as .OST file
    - %AppData%\Local\Microsoft\Outlook
  - Mailbox is synchronized with server
    - Last 12 months of email by default
    - Deduplication is often necessary
    - Maximum 50 GB by default
  - Orphan .OST files can be found

**Outlook Attachment Recovery**

- Outook uses a &quot;Secure Temp Folder&quot; to open attachments
  - _%AppData%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook_
  - _%AppData%\Local\Microsoft\Windows\INetCache\Content.Outlook_ (IE11+)
- Preview and opened attachments can be recovered
  - Prior to outlook 2007, attachments persisted until Disk Cleanup
  - In Outlook 2007+, attachments remain only if message or Outlook is closed before the attachment or in the event of an application crash
  - Outlook back dates creation time of attachment to message time
  - Location
    - HKCU\Software\Microsoft\Office\\&lt;version\&gt;\Outlook\Security\OutlookSecureTempFolder
  - Use MFT $Filename attribute to determine the time the attachment was opened
  - Find contents of folder in $Logfile, USNJournal, and in copies of the $MFT in Volume Shadow Copies

**Other Host-Based Formats**

- Identify installed applications
  - Windows registry is helpful
- Perform keyword searches
  - .txt
  - .htm
  - .eml
  - .msg
- Archives may be corrupted
- Tool: Magnet Axiom

**Calendar and Contacts**

- Appointments
  - .ICS, .SDB, .PST
- Address Books
  - .WAB, .VCF, .PAB, .MAB, .NNT
- Task Lists
  - .SDB, .PST

**Email Encryption**

- S/MIME, PGP/MIME, O365 Msg Encryption
- Look for .pgp or .p7m
- Enterprise Clients typically have the most robust mail archive encryption
  - Key servers makes recovery feasible
- Network-based encryption usually does not hamper forensic efforts
- Encryption is rare

**Microsoft Exchange**

- Exchange 2007+ uses .EDB format
  - Extensible Storage Engine (ESE) format
- .EDB files store mail, attachments, contacts, journal, notes, tasks, calendar, and address book entries
- .log files contain messages not yet written to .EDB
- Exchange is often broken up into multiple storage groups, each with multiple .EDB databases
- Mailboxes can be exported in .PST file format

**Recoverable Items**

- Deletions
  - Items removed from user&#39;s Deleted Items folder; Deleted mail from POP or IMAP accounts
- Purges
  - Temp location for hard-deleted items from Deletions folder and items that exceed retention period. Messages remain during litigation hold.
- Litigation Hold
  - Deleted Items from mailboxes places on hold
- Versions
  - Copy on write changes to items in active mailboxes placed on hold
- Audits
  - Audit log entries for mailboxes with auditing enabled
- Calendar Logging
  - Calendar changes when calendar logging is enabled
- Message Tracing
  - Log showing message details of sent and received mail
- By default, email retained for 14 days and mailboxes for 30 days
- Exchange 2010+ includes indexing and retention of all deleted objects

**Email Server Collection**

1. Full or Logical Disk Image of Server
2. Export of individual mailboxes in their entirety
3. Use of specialized applications to search, filter, and extract messages from the email store

**Online Acquisition - Windows Server Backup**

- WSBExchange.exe
  - Allows backups to be &quot;Exchange Aware&quot;
  - Employs the Volume Shadow Service
  - Written to Virtual Hard Disk (VHD) files

**Exporting Email In Exchange**

- Powershell is now the easiest way to export email
  - _New-MailboxExportRequest -Mailbox buckybarnes -FilePath_ [_\\Server\Folder\barnes.pst_](/%5C%5CServer%5CFolder%5Cbarnes.pst)
- Output can be filtered by nearly every email component
  - _New-MailboxExportRequest -Mailbox buckybarnes -ContentFilter { (body -like &quot;\*HYDRA\*&quot;) -and (received -lt &quot;03/02/2012&quot;) } -Filepath_ [_\\Server\Folder\Barnes\_Filtered.pst_](/%5C%5CServer%5CFolder%5CBarnes_Filtered.pst)
- Automatically includes recoverable items

**Compliance Search**

- Powershell cmdlet -\&gt; New-Compliance Search
  - Security and Compliance GUI in Microsoft 365
- Select mailboxes and build Boolean filters
- Integrates with In-Place eDiscovery
  - Key word statistics help fine-tune searches (# items/size)
  - Can easily export to .PST and place items on &quot;hold&quot;
- _New-Compliance Search -name &quot;Legal Case 81280&quot; -ExchangeLocation &#39;Sales&quot; -ContentMatchQuery &quot;&#39;Widget&#39; and &#39;Johnson&#39;&quot;_
- Security and Compliance
  - Content Search
    - Export .PST

Unified Audit Logs in Microsoft 365

- Search and Export Logs
  - Exchange Online
  - SharePoint Online
  - OneDrive for Business
  - Azure Active Directory
- Must be enabled by Admin
  - _Set-AdminAuditLogConfig_
  - Auto-enabled for every user
  - 90 days retention
- Things to Note
  - Verify default logging is &quot;on&quot;
  - No logoff events
  - IP address and client included

**Office 365 Extractor Script**

- Ref: [https://github.com/PwC-IR/Office-365-Extractor](https://github.com/PwC-IR/Office-365-Extractor)

**Business Email Compromise**

- Compromised Accounts
  - Azure Management Reports
  - M365 Unified Audit Logs
  - Security and Compliance
- Privilege Escalation
  - M365 Admin Portal
  - Admin Audit Logs
  - M365 Unified Audit Logs
  - Security and Compliance
- Data Exfiltration
  - M365 Unified Audit Logs
  - DumpDelegatesandForwardingRules.ps1
  - Cloud App Security

**ISP Legal/Law Enforcement Guides**

- Archived Yahoo! Compliance Guide: [https://cryptome.org/isp-spy/yahoo-spy.pdf](https://cryptome.org/isp-spy/yahoo-spy.pdf)
- Cryptome ISP Spy Guides: [https://cryptome.org/isp-spy/](https://cryptome.org/isp-spy/)
- Facebook Information for Law Enforcement Agencies: [https://www.facebook.com/safety/groups/law/guidelines/](https://www.facebook.com/safety/groups/law/guidelines/)
- Google Transparency Report Help Center: [https://support.google.com/transparencyreport/answer/9713961?hl=en&amp;visit\_id=637669961052831477-1790394080&amp;rd=1](https://support.google.com/transparencyreport/answer/9713961?hl=en&amp;visit_id=637669961052831477-1790394080&amp;rd=1)

**Webmail Browser Artifacts**

- Webmail usage recorded via URLs, Page Titles, and Referrers
  - Accounts
  - Subject Lines
  - Folders
  - Composition
  - Searches

**Yahoo Browser Remnants**

- File in XML format
- Encoded with ROT13

**Hotmail Browser Remnants**

- Gzip files

**Forensic Process**

1. Review installed applications
2. Locate and acquire local email archives
3. Identify and export server-based mailboxes
4. Search for evidence of cloud-based email

  1. Acquire from cloud and/or data carve locally
1. Process and review email using eDiscovery or forensic tools
2. Export relevant files from archive
