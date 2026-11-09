; SecuDrive.iss - Inno Setup 6 script for SecuDrive.exe
;
; Build:   compile this with ISCC.exe (Inno Setup 6.3.1+):
;     ISCC.exe installer\SecuDrive.iss
;   (Add ISCC to PATH, or use the full path to it.  Inno Setup is free:
;    https://jrsoftware.org/isinfo.php )
;
; Signing: uncomment the SignTool= line below (and run `iscc /S` with a
; signing password) once you hold an Authenticode certificate.  See
; installer\SIGNING-NOTES.md for the full explanation + signtool examples.
; Without a certificate leave SignTool commented - the installer still works.

#define MyAppName "SecuDrive"
#define MyAppVersion "1.0.1"
#define MyAppPublisher "SecuDrive Software"
#define MyAppExeName "SecuDrive.exe"
#define MyAppId "{8C4A7E2E-5B43-4C1A-9E7D-3F2C9A1B6D40}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL=https://tirrion.pages.dev/
AppSupportURL=https://github.com/mr-tirrion-toronto/secudrive/issues
AppUpdatesURL=https://github.com/mr-tirrion-toronto/secudrive/releases/latest
DefaultDirName={autopf}\SecuDrive
DefaultGroupName=SecuDrive
DisableProgramGroupPage=yes
; EULA / terms acceptance page (bug #10): the installer will not proceed
; unless the user accepts installer\terms.txt.
LicenseFile=terms.txt
; Privacy notice shown on the Welcome page (bug #10).
InfoBeforeFile=privacy.txt

OutputDir=..\dist
OutputBaseFilename=SecuDrive_Setup
SetupIconFile=..\assets\SecuDrive.ico
UninstallDisplayIcon={app}\SecuDrive.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Authenticode signing.  See installer\SIGNING-NOTES.md before enabling.
; SignTool=sign /n "Your Cert Name" /fd sha256 /tr http://timestamp.digicert.com /td sha256 /a $f

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
; Bug #11: desktop shortcut is opt-OUT - checked by default, uncheck to skip.
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
    GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce

[Files]
Source: "..\dist\SecuDrive.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\SecuDrive"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall SecuDrive"; Filename: "{uninstallexe}"
; Desktop shortcut honours the opt-out task (bug #11).
Name: "{autodesktop}\SecuDrive"; Filename: "{app}\{#MyAppExeName}"; \
    Tasks: desktopicon

[Run]
; Bug #12: register with Windows Security Center once at install time
; (the exe manifests as admin, so the HKLM provider key can be written).
Filename: "{app}\{#MyAppExeName}"; Parameters: "--register-wsc ""{app}\{#MyAppExeName}"""; \
    WorkingDir: "{app}"; StatusMsg: "Registering SecuDrive with Windows Security Center..."; \
    Flags: waituntilterminated skipifsilent
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; \
    Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--unregister-wsc"; RunOnceId: "SecuDriveWscUnreg"

; User quarantine and backup data is intentionally preserved on uninstall.

