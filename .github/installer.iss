#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif
#ifndef MySourceDir
  #error MySourceDir must point to the packaged application directory
#endif
#ifndef MyOutputDir
  #error MyOutputDir must point to the release output directory
#endif

[Setup]
AppId={{CDB2D6EF-7286-48F7-BB60-D0F4E7D73957}
AppName=CF 优选IP
AppVersion={#MyAppVersion}
AppPublisher=Xiaowu7z
AppPublisherURL=https://github.com/Xiaowu7z/RR-Edge-Hunter
AppSupportURL=https://github.com/Xiaowu7z/RR-Edge-Hunter/issues
DefaultDirName={localappdata}\Programs\CF-IP-Optimizer
DefaultGroupName=CF 优选IP
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#MyOutputDir}
OutputBaseFilename=CF-IP-Optimizer-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
UninstallDisplayIcon={app}\CF-IP-Optimizer.exe
CloseApplications=yes
RestartIfNeededByRun=no

[Files]
Source: "{#MySourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\CF 优选IP"; Filename: "{app}\CF-IP-Optimizer.exe"
Name: "{autodesktop}\CF 优选IP"; Filename: "{app}\CF-IP-Optimizer.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加快捷方式："; Flags: unchecked

[Run]
Filename: "{app}\CF-IP-Optimizer.exe"; Description: "启动 CF 优选IP"; Flags: nowait postinstall skipifsilent
