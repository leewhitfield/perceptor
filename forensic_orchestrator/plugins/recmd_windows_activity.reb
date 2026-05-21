Description: Forensic Orchestrator Windows Activity RECmd Batch
Author: Forensic Orchestrator
Version: 1
Id: 1b6eb5ea-38a7-47c5-bbc6-8c1342c723d4
Keys:
    -
        Description: Select
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Select
        Recursive: false
        Comment: CurrentControlSet resolution source.
    -
        Description: ComputerName
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\ComputerName\*
        ValueName: ComputerName
        Recursive: false
        Comment: Computer name from SYSTEM hive control sets.
    -
        Description: TimeZoneInformation
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\TimeZoneInformation
        Recursive: false
        Comment: Time zone values from SYSTEM hive control sets.
    -
        Description: ShutdownTime
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\Windows
        ValueName: ShutdownTime
        IncludeBinary: true
        BinaryConvert: FILETIME
        Recursive: false
        Comment: Last clean shutdown time when present.
    -
        Description: SourceOS Install
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup\Source OS*
        Recursive: true
        Comment: Previous/source OS install metadata.
    -
        Description: Software InstallTime
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: InstallTime
        IncludeBinary: true
        BinaryConvert: FILETIME
        Recursive: false
        Comment: Windows install time from SOFTWARE hive.
    -
        Description: Software InstallDate
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: InstallDate
        Recursive: false
        Comment: Windows install date from SOFTWARE hive.
    -
        Description: NetworkList Profiles
        HiveType: SOFTWARE
        Category: Network
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*
        Recursive: false
        Comment: Connected network profiles.
    -
        Description: NetworkList Signatures
        HiveType: SOFTWARE
        Category: Network
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\*
        Recursive: true
        Comment: Connected network signatures.
    -
        Description: CapabilityAccessManager
        HiveType: SOFTWARE
        Category: User Activity
        KeyPath: Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\*
        Recursive: true
        Comment: Global capability access manager consent data.
    -
        Description: CapabilityAccessManager
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\*
        Recursive: true
        Comment: User capability access manager consent data.
    -
        Description: Run Key
        HiveType: SOFTWARE
        Category: Autostart
        KeyPath: Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: Machine-wide Run autostart values.
    -
        Description: RunOnce Key
        HiveType: SOFTWARE
        Category: Autostart
        KeyPath: Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment: Machine-wide RunOnce autostart values.
    -
        Description: Run Key
        HiveType: NTUSER
        Category: Autostart
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: User Run autostart values.
    -
        Description: RunOnce Key
        HiveType: NTUSER
        Category: Autostart
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment: User RunOnce autostart values.
    -
        Description: Add/Remove Programs Entries
        HiveType: SOFTWARE
        Category: Installed Software
        KeyPath: Microsoft\Windows\CurrentVersion\Uninstall
        Recursive: false
        Comment: Installed software from SOFTWARE hive.
    -
        Description: Add/Remove Programs Entries
        HiveType: SOFTWARE
        Category: Installed Software
        KeyPath: WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
        Recursive: false
        Comment: 32-bit installed software from SOFTWARE hive.
    -
        Description: Add/Remove Programs Entries
        HiveType: NTUSER
        Category: Installed Software
        KeyPath: SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
        Recursive: false
        Comment: Per-user installed software.
    -
        Description: USBSTOR
        HiveType: SYSTEM
        Category: USB
        KeyPath: ControlSet*\Enum\USBSTOR
        Recursive: true
        Comment: USB storage device history.
    -
        Description: USB
        HiveType: SYSTEM
        Category: USB
        KeyPath: ControlSet*\Enum\USB
        Recursive: true
        Comment: USB device history.
    -
        Description: USB WPD Volumes
        HiveType: SYSTEM
        Category: USB
        KeyPath: ControlSet*\Enum\SWD\WPDBUSENUM
        Recursive: true
        Comment: Windows Portable Device volume metadata for USB-backed volumes.
    -
        Description: MountedDevices
        HiveType: SYSTEM
        Category: USB
        KeyPath: MountedDevices
        Recursive: false
        Comment: MountedDevices volume and drive-letter data.
    -
        Description: AppCompatCache
        HiveType: SYSTEM
        Category: Program Execution
        KeyPath: ControlSet*\Control\Session Manager\AppCompatCache
        Recursive: false
        Comment: ShimCache/AppCompatCache raw registry value. Prefer AppCompatCacheParser for full parsing.
    -
        Description: RunMRU
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
        Recursive: false
        Comment: Commands typed into the Windows Run dialog. The key last-write time applies to the first MRUList value.
    -
        Description: TypedPaths
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
        Recursive: false
        Comment: Explorer address bar typed paths. url1 is the most recent value and maps to the key last-write time.
    -
        Description: WordWheelQuery
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
        Recursive: false
        Comment: Explorer search terms and MRU ordering.
    -
        Description: RecentDocs
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
        Recursive: true
        Comment: RecentDocs root and extension-specific MRU lists. Each subkey has its own last-write time.
    -
        Description: UserAssist
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
        Recursive: true
        Comment: UserAssist execution evidence.
    -
        Description: Taskband
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband
        Recursive: true
        Comment: Taskbar usage evidence.
    -
        Description: Office Recent Documents
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Office
        Recursive: true
        Comment: Microsoft Office recent document registry evidence.
    -
        Description: Common Dialog OpenSavePidlMRU
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
        Recursive: true
        Comment: Common dialog Open/Save MRU entries.
    -
        Description: Common Dialog LastVisitedPidlMRU
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
        Recursive: true
        Comment: Common dialog last visited MRU entries.
    -
        Description: ShellBags NTUSER
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\Shell\BagMRU
        Recursive: true
        Comment: ShellBag BagMRU evidence from NTUSER.DAT.
    -
        Description: ShellBags UsrClass
        HiveType: USRCLASS
        Category: User Activity
        KeyPath: Local Settings\Software\Microsoft\Windows\Shell\BagMRU
        Recursive: true
        Comment: ShellBag BagMRU evidence from UsrClass.dat.
