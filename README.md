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

# Windows Search Database

- _C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb_
- Collects info on:
  - Files
  - Emails
  - Content-Related Items
- Tool:
  - ESE Database View (View Windows.edb)
  - Esentutl (Repair corrupted databases)
    - Ref: [https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh875546(v=ws.11)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh875546(v=ws.11))
    - Repair Headers
      - _Esentutl /mh Windows.edb_
    - Recover dirty db
      - _Esentutl /r edb /d_
    - Repair dirty db
      - _Esentutl /p Windows.edb_
  - ESECarve (recover data purged from database)

# Thumbnail Forensics

- Thumbs.db
  - Hidden file in directory where images on machine exist stored in a smaller thumbnail graphics
  - Thumbs.db catalogs pictures in a folder and stores a copy of the thumbnail even if pictures were deleted
  - Win 7/8/10
    - Automatically created anywhere accessed via a UNC path (Local or remote)
- Thumbs.db includes
  - Thumbnail picture of original picture/document thumbnail - even if deleted
  - Last modification time (XP only)
  - Original filename (XP only)
- Tool
  - Thumbs Viewer
- Thumbcache
  - C:\Users\\&lt;User\&gt;\AppData\Local\Microsoft\Windows\Explorer\
    - Thumbnails only
    - Original Location &quot;might&quot; be stored
    - Stored when user switches a folder to thumbnail mode or view pictures via a slideshow
  - Thumbcache\_##.db
  - Tool
    - Thumbcache Viewer
- Mapping Filenames to Thumbcache
  - Copy _C:\ProgramData\Microsoft\Search\Data\Applications\Windows\_ to an export folder named cases
  - Open the command prompt and cd to exported folder \Cases\Windows
  - Run the command &quot;esentutil /r edb /d&quot;

# Recycle Bin Forensics

- Subfolder is created with user&#39;s SID
- Filename in both ASCII and UNICODE
  - $Recycle.bin - Vista/7-10
  - Deleted time and original filename contained in separate files for each deleted recovery file
- Files preceded by $I###### contain
  - Original path and name
    - Recycled date/time
  - Files preceded by $R###### contain
    - Recovery Data
- Tool
  - RBCmd.exe

# Windows 10 Timeline

- _ActivitiesCache.db_
  - SQLite Database Containing 30+ Days of User Activity
  - Application Execution
    - Start Time, End Time, Duration
    - Full Path
  - File Opening
  - URLs Visited
  - Time Zones
  - User removed items persist in the database

- Loc_ation_
  - _C:\Users\\&lt;profile\&gt;\AppData\Local\ConnectedDevicesPlatform\\&lt;\*\&gt;_
    - \&lt;\*\&gt; = L. \&lt;usersname\&gt; | Microsoft Account ID | Azure Account ID

- Microsoft Cloud Accounts can be cross-referenced to account names (email address) via the following registry key
  - _NTUSER.DAT\Software\Microsoft\IdentityCRL\UserExtendedProperties_

- Tables
  - Activity
    - Maintains approx. 7 days of user activity
    - Storage for most recent activity items
    - Relevant Data
      - Application
      - Files Opened/URLs
      - Activity Type
      - Activity Duration
      - Timezone
      - User-removed items
      - Device Id
      - Synced Clipboard (base64)

- Activity\_PackageID
  - Comprehensive view of application execution
  - Linked to other tables via Activity ID field
  - Relevant Data:
    - Application
    - Application Type
    - Application Path
    - Expiration Time

- ActivityOperation
  - Archive &amp; Staging of cloud synchronization
  - Items move here from Activity Table
  - Relevant Data:
    - Application
    - Files Opened/URLs
    - Activity Type
    - Activity Duration
    - Timezone
    - User-removed items
    - Device Id
    - Synced Clipboard

- Win 10 Timeline Synchronization
  - Requires User Opt-In
  - Activities Sync to each device
    - Devices tracked via PlatformDeviceId
    - Supports iOS and Android devices
  - ActivitiesCache.db also stores synched &quot;Cloud Clipboard&quot; data (base64)
  - Activ_ities present in the database can be easily tied to each device via_
    - _NTUSER.DAT/Software/Microsoft/Windows/CurrentVersion/TaskFlow/DeviceCache_

- How to Investigate ActvitiesCache,db
  - Audit applications installed and executed by the user
    - Review application names and full path information in Actvity\_PackageID
  - Review files and URIs opened by each application
    - Search for &quot;http&quot;, file extensions (.pdf, .docx,\&gt; folder names, and keywords
  - Look at all activity around a specific time period
    - Filter table output by date
  - Identify where the user spent the most time
    - &quot;Duration&quot; information located in payload of ActivitiesOperations table
  - Geolocate via time zone information
    - Located in Payload of ActivityOperations table
  - Identify items removed by the user
    - ActivityStatus = 3 in Activity table OperationType = 3 in ActivityOperations table
  - Review device information to identify other synced devices
    - Is there relevant data tied to more that one PlatformDeviceId in Activity or ActivityOperations?
- Tool
  - WxTCmd.exe

# System Resource Usage Monitor (SRUM)

- Processes Run
  - AppID and Path
  - User Executing App
  - App Energy Usage
  - Bytes Sent
  - Bytes Received
  - Disk Read/Writes
- App Push Notification
  - AppID
  - User
  - Payload Size
- Network Activity
  - Network Interface
  - Network Name
  - Bytes Sent
  - Bytes Received
  - Connection Time &amp; Duration
- Energy Usage
  - Charge Capacity
  - Charge Level
  - Time
  - Time on AC/DC Power
- 30 - 60 days of historical system performance
- Location
  - Software\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions
    - Windows Network Data Usage Monitor
    - Application Resource Usage Provider
    - Windows Connectivity Usage Monitor
  - C:\Windows\System32\SRU
- Examine with System Networks with ESEDatabaseView
  - L2ProfileId - Network Identifier
  - SOFTWARE\Microsoft\WlanSvc\Interfaces\{GUID}\Profiles
    - Metadata
      - Channel Hints
- Tool
  - SRUM\_DUMP

# Event Logs

**Event Log Overview**

- What happened
  - EventID
  - Event Category
  - Description
- Date/Time
  - Timestamp
- Users Involved
  - User Account
  - Description
- Systems Involved
  - Hostname
  - IP Address
- Resources Accessed
  - File
  - Folders
  - Printers
  - Services

**Event Log Location**

- .evtx
- %systemroot%\System32\winevt\logs

**Event Log Types**

- Security
  - Records access control and security settings information
  - Events based on audit and group policies
  - Example: Failed logon; folder access
- System
  - Contains event related to Windows services, system components, drivers, resources, etc.
  - Example: Service stopped; system rebooted
- Application
  - Software events unrelated to operating system
  - Example: SQL server fails to access a database
- Custom
  - Custom application logs
  - Examples: Server logs, including Directory Services, DNS Server, and File Replication Service
- Setup
  - Records installation and update information for Windows
- Forwarded Events
  - Repository for events retrieved from other systems
- Applications and Services
  - Contains over 60 logs
  - Useful logs include Task Scheduler, Remote Desktop, Windows Firewall, and Windows Defender
- Sort Folder by Size

**Security Log**

- Account Logon
  - Events stored on system who authorized logon (that is, domain controller or local system for non-domain accounts(
- Account Mgmt (Default)
  - Account maintenance and modifications
- Directory Service
  - Attempted access of Active Directory objects
- Logon Events (Default)
  - Each instance of logon/logoff on local system
- Object Access
  - Access to objects identified in system access control list
- Policy Change (Default)
  - Change of user rights, audit policies, or trust policies
- Privilege Use
  - Each case of an account exercising a user right
- Process Tracking
  - Process start, exit, handles, object access, etc.
- System Events
  - System start and shutdown; actions affecting security log

**Profiling Account Usage**

- Scenario
  - Determine which accounts have been used for attempted logons
  - Track account usage for known compromised accounts
- Relevant Event IDs
  - 4624 - Successful Logon
  - 4625 - Failed Logon
  - 4634 / 4647 - Successful Logoff
  - 4672 - Account Logon with Superuser rights (Administrator)
- Investigative Notes
  - Event descriptions provide a granular view of logon information
  - Windows does not reliably record logoffs (ID 4634) so also look for ID 4647 -\&gt; User initiated logoff for interactive logons
  - Logon events not recorded when backdoors, exploited services, or similar malicious means are used to access a system
  - Note: Logon Type, Account, Timestamp, EventID, Computer
- Logon Types
  - 2 - Logon via console (keyboard, server KVM, or virtual client)
  - 3 - Network Logon
  - 4 - Batch logon; often used by scheduled tasks
  - 5 - Windows service logon
  - 7 - Credentials used to lock or unlock screen; RDP session reconnect
  - 8 - Network logon sending credentials in cleartext
  - 9 - Different credentials used than logged on user - RunAs /netonly
  - 10 - Remote interactive logon (Remote Desktop Protocol)
  - 11 - Cached credentials use to logon - system likely offline from DC
  - 12 - Cached Remote Interactive (Similar to Type 10)
  - 13 - Cached unlock (similar to Type 7)
- Identifying Logon Sessions
  - User the LogonID value to link a logon with a logoff and determine session length
- Tracking a Brute Force
  - Note Logon Type, Account Name, Workstation Name, Source Network Address, EventID
- Tracking Remote Desktop Protocol
  - Scenario
    - Track Remote Desktop Protocol logon to target machines
  - Relevant EventIDs
    - 4778 - Session Reconnected
    - 4779 - Session Disconnected
  - Investigative Notes
    - Records hostname and IP address of remote machine making the connection (sent via RDP client application)
    - Not a reliable indicator of all RDP activity - intended to record &quot;reconnects&quot;
      - Valuable to fill in gaps since RDP reconnects are often Type 7 lgons
    - Also used to track &quot;Fast User Switching&quot; sessions
    - The auxiliary logs RemoteDesktopServices-RDPCoreTS and TerminalServices-RdpClient record complementary info
  - EventID 4624 - Logon
    - Logon Type: 10
    - Account Name: \*
    - Source Network Address: \*
  - EventID 4778
    - Account Name: \*
 Account Domain: \*
    - Logon ID: \*
    - Session Name: \*
 Client Name: \*
    - Client Address: \*

**Analyzing Files and Folder Access**

- Scenario
  - Identify which users have attempted to access a protected file, folder, registry key, or other audited resource
- Relevant EventIDs
  - 4656 - Handle to object requested
  - 4660 - Object deleted
  - 4663 - Access attempt on object (read, write, delete. …)
- Investigative Notes
  - Event Includes timestamp, file or folder name, and user account that attempted access
  - Filter by 4656 Failure Events to identify users attempting unauthorized access
  - Review 4663 events to identify what user actions occurred
  - Object auditing can quickly fill logs and requires tuning
- Audit Success
  - Account Name:
  - Object Name:
  - Process Name:
  - Accesses:
  - Event ID:
- Audit Failure
  - Account Name
  - Object Name
  - Access Reasons
  - Event ID
- Microsoft Office Oalerts
  - Scenario
    - Identify file interaction and alerts generated by Microsoft Excel, Word, Outlook, PowerPoint, Access, OneNote, and Publisher
  - Relevant Event IDs
    - 300 - Office Alert
  - Investigative Notes
    - Microsoft dialog alerts are recorded as events in Oalerts.evtx
    - File access, modification, and deletes may be recorded Unauthorized access/permissions issues trigger events
    - Outlook activity is particularly valuable, as little other logging exists
    - Oalerts is not a comprehensive source of all Office activity



**Time Manipulation**

- Scenario
  - Find evidence of time changes accomplished by user accounts
- Relevant Event IDs
  - 1 - Kernel-General (System Log)
  - 4616 - System time was changed (Security log)
- Investigative Notes
  - New in Win8: System log events include user account information (previously only available in the Security log)
  - Security State Change Auditing must be enabled to log time changes into the Security log

**Geolocation Information**

- Scenario
  - Determine what wireless networks the system associated with and identify network characteristics to find location
- Relevant Event IDs
  - 11000 - Wireless network association started
  - 8001 - Successful connection to wireless network
  - 8002 - Failed connection to wireless network
  - 8003 - Disconnect from wireless network
  - 6100 - Network diagnostics (System log)
- Investigative Notes
  - New custom log introduced with Vista and Server 2008: Microsoft-Windows-WLAN-AutoConfig Operational.evtx
  - Contains SSID and BSSID (MAC Address), which can be used to geolocate wireless access point \*(no BSSID on Win8+)
  - Shows historical record of wireless network connections
- 8001
  - SSID
  - BSSID
  - Authentication
  - Logged
  - Pair 8001 and 8003 events to find session length
- Source: Diagnostics-Networking
  - System Log
  - Visible networks
    - Date/Time
    - Interface Adapter
    - SSID
    - BSSID
    - Signal Strength
    - RARE!

**Event Log Summary**

- Logons
  - Location: Security
  - Event IDs: 4624, 4625, 4634, 4674, 4672, 4800, 48014, 4, 4625, 4634
- RDP
  - Location: Security | RemoteDesktopServices-RDPCoreTS | TerminalServices-RDPClient
  - Event IDs: 4778, 4779 | 131 | 1024, 1102
- Object Access
  - Location: Security | Oalerts
  - Event IDs: 4656, 4660, 4663 | 300
- Time Change
  - Location: System | Security
  - Event IDs: 1 | 4616
- Ext. Devices
  - Location: System | Security
  - Event IDs: 20001 | 4656, 4663, 6416
- Wireless
  - Location: WLAN-AutoConfig | System
  - Event IDs: 8001, 8002, 11000 | 6100

Tools

- Event Log Explorer
- Evtx Explorer

Ref: [https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/+](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/+)

Ref: [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)

# Web Browsers

**Overview**

- What websites did the user visit?
  - History
  - Cache
  - Cookies
  - Session Recovery
  - Typed URLs
  - Prefs
- How many time was the site visited?
  - History
- When was a site visited?
  - History
  - Cookies
  - Cache
  - Session Recovery
- What websites were saved by the user?
  - Bookmarks
- Were any files downloaded?
  - Download History
  - Cache
  - Prefs
- Cane we identify any usernames?
  - History
  - Cookies
  - Cache
  - Auto Complete
  - Session Recovery
  - Prefs
- What was the user searching for?
  - Auto-Complete
  - Cache

**Browser Languages**

- JavaScript
- CSS
- HTML5

**Chrome**

- Artifact Locations:
  - %USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default
    - SQLite
    - JSON
    - SNSS (Session Saver files)
- History
  - Records websites visited by data and time
    - Details stored for each local user account
    - URL
    - Page Title
    - Referrer Page
    - Visit Count (Frequency)
  - History SQLite Database
  - 90 Days
- History Database Tables
  - Downloads: Download Manager
  - Downloads\_url\_chains: Download Manager
  - Keyword\_search\_terms: Typed Search Terms
  - Segments &amp; Segments usage: Frequently used sites
  - URL, visits: URLs visited (History)
  - Visit\_source: Synchronized data
- URL/Visit table
  - What was the complete URL that was visted? - url
  - What was the title of the page visited? - title
  - What times was the site last visited? - visit\_Time (cross reference using id from url table)
  - When was the site last visited? - last\_visit\_time
  - How many visits were made to the site? - visit\_count
  - Was the URL typed by the user? - typed\_count
  - What page led the user to this one? - From\_visit
  - How long was the page viewed? - visit\_duration
  - How did the user request the page? - transition
- Transition Types
  - 0 - Type: User clicked a link
  - 1 - Typed: URL typed in address bar (same as IE typed URLs)
  - 2 - Auto\_Bookmark: Via a suggestion in the Chrome UI (NOT a user favorite)
  - 3 - Auto\_Subframe: Content loaded in a non-top-level frame (advertisement)
  - 4 - Manual\_Subframe: User request to load content in non-top-level frame
  - 5 - Omniibox Generated: Suggested based on user typing but user did NOT see URL
  - 6 - Start\_Page: Home page of a tab
  - 7 - Form\_Submit: User filled out information in a form and submitted
  - 8 - Reload: Page refreshed
  - 9 - Keyword: Keyword typed to identify site (for example, &quot;Wired&quot; \&lt;TAB\&gt;)
  - 10 - Keyword Generated: The actual URL generated (and visited) as a result of keyword
  - Ref: [https://kb.digital-detective.net/display/BF/Page+Transitions](https://kb.digital-detective.net/display/BF/Page+Transitions)
- Cache
  - %AppData%\Local\Google\Chrome\User Data\Default\Cache
  - Index - hash table of stored URLs
  - Data\_# - block storage for small files \&lt; 16 KB
  - F\_###### - individual cached files \&gt; KB
  - Tool: ChromeCacheView
- Cache Timestamps
  - Last Accessed - The last time cached content was used (UTC)
  - Server Time - The time file was stored locally (First known visit); creation time of cached file (UTC)
  - Server Last Modified - The last time content was changed on the web server; Set by the website and stored in UTC
  - Expire Time - Used by the cache to age out old versions of pages; Set by the website and stored in UTC
- Cookies
  - SQLite Format
  - Encrypted with DPAPI
  - Decryption possible on live system with user logged in
  - Contents of cookies rarely used in invesitigation
- Cookie Questions
  - What website domain/page issued the cookie? - host\_key / path
  - What is the cookie name? - name
  - What values/preferences were stored - value/encrypted\_value
  - When was the cookie created? - creation\_utc
  - When was the cookie/site last accessed? - last\_access\_utc
- HTML5 Web Storage
  - Preferences, keywords, visit tracking, usernames, offline files, not expiration and cleared along with cookies
  - Chrome: LevelDB in Local Storage folder (prev. SQLite)
    - _%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Local Storage_
  - Firefox: Located in webappstore.sqlite database
  - IE/EdgeHTML: .XML file sin the DOMStore folder
    - _%USERPROFILE%\AppData\Local\Microsoft\Internet Explorer\DOMStore_
    - _%UserPROFILE%\AppData\Local\Packages\microsoft.microsoftedge\_\&lt;APPID\&gt;\AC\#!001\MicrosoftEdge\User\Default\DOMStore_
- Chrome HTML5 File System
  - %AppData%\Local\Google\Chrome\User Data\Default\File System
  - Where sites can store files
- Preferences
  - JSON file containing configuration data
  - Located in Chrome profile folder (\Default)
  - Note
    - Clear\_data - previously cleared artifacts
    - Savefile - last saved location
    - Selectfile - last opened from location
    - Content\_settings
      - Per\_host\_zoom\_levels - sites that have been zoomed by user
      - Geolocation - sites that have been allowed to geolocate the browser
      - Media\_engagement - significant media play (at least 7 seconds and have an non-muted audio track
      - Site\_engagement - tracks legitimate user engagement with the site
      - Sound - sites that have been permanently muted by the user
    - Synchronization Data
      - Account\_info - google account last used to sign-in
      - Signin - authentication info related to google account
      - Last\_synced\_time - last synced to cloud
      - Zerosuggest - catalogs recent search terms (base64)
- Auto-Complete
  - History
    - Visited sites
    - Search engine typing (keyword\_search\_terms)
  - Web Data
    - Items typed into web forms
    - Note: autofill table
  - Shortcuts
    - What was typed into &quot;Omnibox&quot;
    - Note: Omni\_box\_shortcuts table
  - Network Action Predictor
    - Items prefetched and triggered by typing
    - Note: network\_action\_predictor table
  - Login Data
    - Saved credentials
    - URL and username also recorded when user opts out
- Session Recovery
  - Uses SNSS (session saver) format
    - Version \&lt; 86
      - Current Session and Current Tabs
      - Last Session and Last Tabs
    - Version 86+
      - Sessions folder
      - Session\_\&lt;timestamp\&gt;
      - Tabs\_\&lt;timestamp\&gt;
  - Tools
    - Browser History Examiner
    - Axiom
    - X-Ways
    - Chromagnon
      - Chromagnon.py &quot;Last Session&quot;
    - Strings
      - Strings.exe &quot;Last Session&quot;
- Synchronization
  - Visit\_source table identifies synced history entries via the source field
    - 0 - Synced
    - 1 - User Browsed
    - 2 - Extension
    - 3 - Firefox Import
    - 4 - IE Import
    - 5 - Safari Import
    - 6 - Chrome (Edge)
    - 7 - EdgeHTML
  - Match &quot;id&quot; to visits table
- Master Tool
  - Hindsight

**Chrome/Edge Analysis Cookbook**

1. Determine Sites Visited

  1. Review Current History Data

    1. Search Keywords
    2. Review Transition info for Typed URLs
    3. Document Top Sites
  1. Audit Preferences file for visited and synchronization info
  2. Search Current and Last Session Files
  3. Audit Bookmarks and (Collections - Edge Only)
  4. Look for other profiles
1. Fill in Evidence Gaps

  1. Review Cache file domains

    1. Analyze specific file types of interest
  1. Review Cookie domains
  2. Search HTML5 data in Local Storage folder
  3. Parse Download History
  4. Analyze Web Data, Shortcuts, and Network Predictor entries
  5. Audit chrome browser extensions
1. Deep Dive Analysis

  1. Review memory-based artifacts

    1. Incognito artifacts
  1. Carve deleted SQLite entries
  2. Review Sync Data database
  3. Audit Chrome Jumplist entries
  4. Target analysis using Volume Shadow Copies

**Edge**

- _%AppData%\Local\Microsoft\Edge\User Data\Default_
  - Internet History
    - History, Top Sites
  - Cache Files
    - Data\_#, f\_######
  - Cookies/Web Storage
    - Cookies/Local Storage Folder
  - Bookmarks
    - Bookmarks, Bookmarks.bak
  - Download History
    - History
  - Auto Complete\Form Data
    - History, Web Data, Login, Data, Network Action Predictor
  - Installed Extensions
    - Extensions Folder
  - Session Recovery
    - Current Session, Current Tabs, Last Session, Last Tabs
  - Synchronization
    - Sync Data
- Chrome/Edge: Examining Downloads (History - Table: Downloads)
  - What was the filename?
    - Target\_path
  - Where was the file downloaded from?
    - Tab\_referrer\_url, tab\_url +(referrer &amp; download\_url\_chains)
  - Where was the file saved?
    - Target\_path
  - When did the download start/end?
    - Start\_time, end\_time
  - How large was the download?
    - Total\_bytes
  - Was the download successful?
    - State, interrupt\_reason
  - Was the file opened (via download mgr)?
    - Opened, last\_access\_time
  - Did the Chrome flag the content of the file?
    - Danger\_type
- Chrome/Edge Download: Additional Metadata
  - State
    - 0 - In Progress
    - 1 - Complete
    - 2 - Cancelled
    - 3 - Interrupted
    - 4 - Blocked
  - Interrupt\_reason (selected)
    - 0 - None
    - 1 - File (generic)
    - 2 - Access Denied
    - 3 - No Space
    - 5 - Filename too long
    - 6 - File too large
    - 7 - Virus Infected
    - 12 - Failed Security
    - 20 - Network Error
    - 40 - User Cancelled
    - 41 - User Shutdown
    - 50 - Browser Crash
  - Danger\_type
    - 0 - Not Dangerous
    - 1 - Dangerous URL
    - 3 - Dangerous Content
    - 4 - Maybe Dangerous
    - 5 - Uncommon Content
    - 6 - User Validated
    - 7 - Dangerous Host
    - 8 - Potentially Unwanted
    - 11 - Password Protected
    - 13/14 - Sensitive Content
- Chrome/Edge Extensions
  - Manifest.json (in each extension folder)
- Bookmarks
  - Bookmarks, Bookmarks.bak
- Edge Collections
  - %AppData%\Local\Microsoft\Edge\User Data\Default\Collections\collectionsSQLite
    - Collections\_items\_relationship
      - Item\_id, parent\_id
    - Collections
      - Parent\_id -\&gt; id
    - Items
      - Item\_id -\&gt; id
- Edge Privacy Settings
  - Found in &#39;preferences&#39; table
  - Data deletion options
- Chrome/Edge Profiles
  - _%AppData%\Local\Microsoft\Edge\User Data\_
  - Each profile maintains a complete set of databases
  - Profiles can be tied to a name or email (found in &#39;preferences&#39; file)
- Edge Synchronization
  - &#39;preferences&#39; table
  - Syncs
    - Web Data (Form Data)
    - Bookmarks
    - Extensions
    - Login Data (Passwords Encrypted)
    - Collections

**Internet Explorer**

- IE 11
  - Metadata - Cache, History, Download History, Cookies
    - %USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV\*.dat
  - Storage - Cache, Cookies
    - %USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache\IE
    - %USERPROFILE%\AppData\Local\Microsoft\Windows\INetCookies\Low
- IE 10
  - Metadata - Cache, History, Download History, Cookies
    - %USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV\*.dat
  - Storage - Cache, Cookies
    - %USERPROFILE%\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5
    - %USERPROFILE%\AppData\Local\Microsoft\Windows\Temporary Internet Files\Low\Content.IE5
    - %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Cookies
    - %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Cookies\Low
- IE 8 &amp; IE 9
  - Metadata stored in Index.dat files
  - History
    - %USERPROFILE%\AppData\Local\Microsoft\Windows\History\History.IE5
    - %USERPROFILE%\AppData\Local\Microsoft\Windows\History\Low\History.IE5
  - Cache
    - %USERPROFILE%\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5
    - %USERPROFILE%\AppData\Local\Microsoft\Windows\Temporary Internet Files\Low\Content.IE5
  - Cookies
    - %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Cookies
    - %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Cookies\Low
  - Download History
    - %USERPROFILE%\AppData\Roaming\Microsoft\Windows\IEDownloadHistory
- WebcacheV\*.dat
  - Table: Containers
    - ContainerID - Identifier for each table assigned to an IE artifact
    - LastAccessTime - Last update time for table
    - Name - Type of table (&quot;History&quot; == IE History)
    - Directory - Location of artifacts in the filesystem
  - History table
    - AccessedTime - Access time of object referenced in URL field
    - AccessCount - Number of times URL visited - \*\*Not Reliable\*\*
    - Url - Resource being accessed (website, file, or other object)
  - Download History
    - Iedownload table
    - Response Headers field contains a wealth of information about each download in hex Unicode format
    - Filename
    - File Size
    - Originating URL
    - Referring URL
    - Download Destination
    - Time of Download (Accessed Time)
  - Local Files Access (History table)
    - [file:///C:/\&lt;filename\&gt;](/C:%5C%3Cfilename%3E)
  - Other browser history can make its way into the IE history tables
    - &quot;@microsoft-edge:&quot;
  - Cache
    - Filename/FileSize - Name and size (in bytes) of cached file on disk
    - SecureDirectory - Location of file within cache subdirectories
    - AccessCount - Number of uses of cached content
    - URL - Origin of cached content
  - Cookies
    - Filename - Cookie filename on disk
    - URL - Issuing domain of cookies
    - AccessCount - How many times cookies has been passed to site
    - CreationTime - First time cookie saved to system (UTC)
    - ModifiedTime - Last time website modified cookie (UTC)
    - AccessedTime - Last time cookie was passed to website (UTC)
    - ExpiryTime - When cookie will no longer be accepted (UTC)
  - Universal Apps
    - Twitter App, etc
    - %USERPROFILE%\AppData\Local\Packages
  - Look for transaction logs
    - Read headers: esentutl /mh WebCacheV01.dat
    - Recover dirty db: esentutl /r V01 /d
  - Auto-Complete
    - Typed URLs
      - NTUSER\Software\Microsoft\InternetExplorer\TypedURLs (IE 9)
      - NTUSER\Software\Microsoft\InternetExplorer\TypedURLsTime (IE 10+)
    - Credential Manager/Windows Vault
      - DPAPI Encrypted
      - Website Usernames and Passwords
      - Network, Exchange Server, RDP, and FTP passwords
      - Stored as a single .vcrd file
      - %USERPROFILE%\AppData\Local\Microsoft\Vault\{GUID}
      - %USERPROFILE%\AppData\Roaming\Microsoft\Vault\{GUID}
      - \Windows\System32\config\systemprofile\AppData\Local\Vault\{GUID}
      - \Windows\System32\config\systemprofile\AppData\Roaming\Vault\{GUID}
      - Tool: WebBrowserPassView (can decrypt on live machines)
  - Session Recovery
    - Creation time of .dat files in Active folder = session start
    - Creation time of .dat files in LastActive folder = session end
    - Structure Storage Format
      - Tool: Structure Storage Viewer
      - Tool: ParseRS
    - Windows 7/8/10
      - %USERPROFILE%/AppData/Local/Microsoft/Internet Explorer/Recovery/Active (Current Session)
      - %USERPROFILE%/AppData/Local/Microsoft/Internet Explorer/Recovery/Last Active (Last Session)
      - %USERPROFILE%/AppData/Local/Microsoft/Internet Explorer/Recovery/Immersive/Active (Current Session - Modern IE)
      - %USERPROFILE%/AppData/Local/Microsoft/Internet Explorer/Recovery/Immersive/Last Active (Last Session - Modern IE)
      - %USERPROFILE%/AppData/Local/Microsoft/Internet Explorer/Recovery/High/Active (Current Session - High Integrity)
      - %USERPROFILE%/AppData/Local/Microsoft/Internet Explorer/Recovery/High/Active (Last Session - High Integrity)
    - Windows XP (IE8 Only)
      - %USERPROFILE%/Local Settings/Application Data/Microsoft/Internet Explorer/Recovery/Active (Current Session)
      - %USERPROFILE%/Local Settings/Application Data/Microsoft/Internet Explorer/Recovery/Last Active (Last Session)
  - Synchronization
    - Determine if enabled
      - SOFTWARE\Microsoft\Windows\CurrentVersion\SettingsSync\BrowserSettings\\&lt;Browser Name\&gt;
    - If turned off the following key is created
      - NTUSER\ControlPanel\Usage\SystemSettings\_SyncSettings\_SyncBrowsingSettings\_Toggle
    - Synced
      - History
      - Typed URLs
      - Bookmarks
      - Tabs
      - Preferences
      - Passwords
    - Survives Clear
      - Local
        - All WebCache entries removed
        - Tab roaming folders cleared
      - Remote
        - Tab roaming folders cleared
      - All WebCache data persists
    - Key Artifact: TabRoaming Sessions
      - %AppData%\Local\Microsoft\InternetExplorer\TabRoaming
    - Tabs - Parse MachineInfo.dat and Tab .dat files
    - History - Compare SyncTime and AccesTime for entry in WebCacheV\*.dat. If times differ by more than +/- 5 seconds, it likely originated from a different system. If ExpiryTime = 0, a history entry was recorded in WebCacheV\*.dat due to a sync operation
  - Overview
    - Internet History - WebcacheV\*.dat, Session Recovery {GUID}.dat
    - Cache Files - WebcacheV\*.dat
    - Cookies/WebStorage - WebCacheV\*.dat / DOMStore
    - Bookmarks - .url files
    - Download History - WebCacheV\*.dat
    - TypedURLs - Registry
    - Web Passwords - .vcrd files
    - Synchronization - WebCacheV\*.dat &amp; TabRoaming {GUID}.dat

**IE/EdgeHTML Analysis Cookbook**

1. Determine Sites Visited

  1. Review Current History Data

    1. Search Keywords
    2. Validate that your tool reviews all History tables in ESE database
    3. Analyze Session Recovery files
    4. Check for evidence of synchronization
  1. Review TypedURLs key
  2. Audit Bookmarks
1. Fill in Evidence Gaps

  1. Review Cache file domains

    1. Analyze specific file types of interest
  1. Review Cookie domains
  2. Search HTML5 DOMstore
  3. Parse Download History
  4. Review Relevant Modern UI artifacts
  5. Check for Roaming Tab files
1. Deep Dive Analysis

  1. Review memory-based artifacts

    1. InPrivate Browsing Artifacts
  1. Recover dirty ESE database entries
  2. Carve deleted ESE entries
  3. Review IT/EdgeHTML Jumplist entries
  4. Check LNK files for website data
  5. Target analysis using Volume Shadow Copies
1. Tools - IECacheView, IECookiesView, IEHistoryView

**Firefox**

- File Locations
  - History, Cookies, Bookmarks, Auto-Complete
    - %USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\\&lt;random text\&gt;.default
  - Cache
    - %USERPROFILE%\AppData\Local\Mozilla\Firefox\Profiles\\&lt;random text\&gt;.default\Cache
- Majority SQLite DB with some JSON
- Important DB files
  - Places.sqlite - History, Bookmarks, Auto-Complete, Downloads
  - Formhistory.sqlite - Auto-complete form data
  - Cookies.sqlite - Cookies
  - Webappsstore.sqllite - HTML5 Web Storage
  - Extensions.sqlite - Firefox
- Places.sqlite
  - What was the complete URL that was visited? - url
  - What was the title of the page visited? - title
  - When was the site first visited? - visit\_date\*
  - When was the site last visited - visit\_date\*
  - How many visits were made to the site? - visit\_count
  - Was the URL typed by the user? - typed
  - Was the page retrieved without any user actions? - hidden
  - What page led the user to this one? - from\_visit
  - How did the user request the page? - visit\_type
- Visit\_type
  - 1 - User followed a link and the page was loaded
  - 2 - User typed the URL to get to the page (with or without auto-complete)
  - 3 - User followed a bookmark to get to the page
  - 4 - Indicates some inner content was loaded, such as images and iframes
  - 5 - Page accessed due to a permanent redirect (HTTP 301 status code)
  - 6 - Page accessed due to temporary redirect (HTTP 302 status code)
  - 7 - File indicated by history was downloaded (non-HTML content)
  - 8 - User followed a link that loaded a page in a frame
- Cache
  - %USERPROFILE%\AppData\Local\Mozilla\Firefox\Profiles\\&lt;random text\&gt;.default\Cache - \&lt;= Version 32
  - %USERPROFILE%\AppData\Local\Mozilla\Firefox\Profiles\\&lt;random text\&gt;.default\cache2 - \&gt;= Version 32
  - URL
  - Num Times Fetched
  - Is the File Present?
  - Filename
  - File Type
  - File Size
  - Last Modified Time
  - Last Fetched Time
  - Response Header
- Cookies
  - Cookies.sqlite
    - What website domain issued the cookie? - host
    - What is the cookie name? - name
    - Was the cookie issued in a secure connection? - isSecure
    - What values/preferences were stored? - value
    - When was the cookie created? - creationTime
    - When was the cookie/site last accessed? - lastAccessed
- Download History
  - Places.sqlite - table: moz\_annos
    - What was the filename? - place\_id (ref. moz\_places)
    - Where was the file downloaded from? - place\_id (ref. moz\_places)
    - Where was the file saved? - Anno\_attribute\_id 4
    - When did the download end? - Anno\_attribute\_id 5 (endTime)
    - How large was the download? - anno\_attribute\_id 5 (fileSize)
    - Was the download successful? - anno\_attribute\_id 5 (state)
  - Firefox 26+ places.sqlite
  - Firefox 3-25: downloads.sqlite
  - Changes to default download directory are recorded in prefs.js
- Auto-Complete
  - Formhistory.sqlite
    - What type of form was the data entered into? - filename
    - What was the data typed by the user? - value
    - How many times has value been used? - timesUsed
    - When was the data first typed in? - firstUsed
    - When was the last time the data was used? - lastUsed
  - Use Dcode to decode times (UNIX epoch time)
- Session Restore
  - Sessionstore.jsonlz4
    - Javascript format (compressed)
    - Deleted when browser is closed
  - Sessionstore-backups
    - Contains older sessions
    - Deleted when browser history is cleared
- Extensions
  - Extensions.json
    - What extensions were installed? - name
    - What version of extension? - version
    - Extension information page? - SourceURI
    - When was the extension installed? installDate
    - When was the extension last updated? updateDate
    - Was the extension enabled? - active
- Synchronization
  - Synced
    - History
    - Bookmarks
    - Preferences
    - Form History
    - Extensions
    - Passwords (encrypted)
    - Tabs
    - Cookies (not all)
    - Downloads (visit\_type = 7)
  - Indications of synced data
    - Visit\_type =1 and no from\_visit ID
    - No data present in description and preview\_image\_url fields
    - No entries in favicons.sqlite
    - No entries in webappstore.sqlite
    - No cached files from site
    - Small number of cookies associated with domain
    - Visit\_type = 7 and no moz\_annos
  - Synced Data Persistent after clear
    - Local System
      - Places.sqlite cleared
        - Download History Cleared
      - Formhistory.sqlite cleared
      - Cookies.sqlite cleared
      - Cache2 entries deleted
      - Sessionstore-backups folder deleted
    - Remote System
      - All existing data and synced data persist
      - Interestingly, &quot;Delete Page&quot; and &quot;Forget About This Site&quot; options remove entries on both local and remote systems

**Firefox Analysis Cookbook**

1. Determine Sites Visited

  1. Review Current History Data

    1. Search Keywords
    2. Review VisitType for TypedURLs
    3. Analyze privacy settings
    4. Check for evidence of synchronization
  1. Analyze Session Restore files
  2. Audit Bookmarks
  3. Look for other profiles
1. Fill in Evidence Gaps

  1. Review Cache file domains

    1. Analyze specific file types of interest
  1. Review Cookie domains
  2. Search HTML5
  3. Webappstore data
  4. Parse Download History
  5. Analyze Formhistory
  6. Audit installed browser extensions
1. Deep Dive Analysis

  1. Review memory-based artifacts

    1. Private Browsing Artifacts
  1. Carve deleted SQLite entries
  2. Review Firefox Jumplist entries
  3. Target analysis using Volume Shadow Copies
1. Tools - MZCacheView, FireFoxDownloadsView, BrowserHistoryView, dejsonlz4



**Private Browsing**

- Internet Explorer/EdgeHTML
  - History not saved
  - Cookies are not created
  - TypedURLs and Form data no saved
  - Cached files are created but deleted at end of session
  - Can be disabled using Group Policy or via Registry
  - Can be recovered via file undeletion
    - Cache Files
    - Automatic Crash (Session) Recovery files
  - Artifacts can be found
    - Unallocated space/pagefile.sys
    - Memory
  - User parseRS on session recovery file
- Chrome/Edge/Firefox
  - Artifacts in memory
  - Downloaded files persist
  - Bookmarks are maintained
- Tor Private Browsing
  - Application Execution
    - Prefetch: TOR.EXE, START TOR BROWSER.EXE
    - UserAssist: Start Tor Browser.exe
    - SRUM: TOR.EXE, START TOR BROWSER.EXE
  - \Data\Browser folder contains Firefox databases
  - \Data\Tor folder contains preferences and status files
    - &quot;State&quot; text file can show TOR version and last execution time
- Identify selective deletes
  - Gaps in the database or significant time gaps
  - Deleted data cane be recovered by carving the unallocated space within the database
    - Sqlparse.py -f places.sqlite -o places\_out.tsv
    - ESECarve
      - -y (deduplicates)
