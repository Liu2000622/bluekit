; BlueKit 安装程序（Inno Setup 6）
; CI 用法（两条腿共用本脚本，用 /D 宏区分）：
;   ISCC.exe /DAppVersion=0.5.0 /DOutputName=BlueKit-windows-x64-setup /DMinVer=6.3    build\bluekit.iss
;   ISCC.exe /DAppVersion=0.5.0 /DOutputName=BlueKit-win7-x64-setup    /DMinVer=6.1sp1 build\bluekit.iss
; 输入：PyInstaller 产物 dist\BlueKit\（先跑 pyinstaller build\bluekit.spec）
; 默认装到用户目录（无需管理员权限），可在向导里改。

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef OutputName
  #define OutputName "BlueKit-setup"
#endif
#ifndef MinVer
  #define MinVer "6.3"
#endif

[Setup]
AppId={{B7E3F2D4-6C1A-4E8F-9B2D-5A0C4E7F1A93}
AppName=BlueKit
AppVersion={#AppVersion}
AppPublisher=领个羊
DefaultDirName={autopf}\BlueKit
DefaultGroupName=BlueKit
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputBaseFilename={#OutputName}
SetupIconFile=bluekit.ico
UninstallDisplayIcon={app}\BlueKit.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion={#MinVer}

[Languages]
Name: "chinesesimplified"; MessagesFile: "ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务:"

[Files]
Source: "..\dist\BlueKit\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\BlueKit"; Filename: "{app}\BlueKit.exe"
Name: "{autodesktop}\BlueKit"; Filename: "{app}\BlueKit.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\BlueKit.exe"; Description: "立即启动 BlueKit"; Flags: nowait postinstall skipifsilent

[Code]
// 升级安装前先静默卸载旧版本，避免新旧 Python 运行时文件混杂导致启动异常
procedure UninstallPrevious();
var
  Key, Uninst: String;
  ResultCode: Integer;
begin
  Key := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#emit SetupSetting("AppId")}_is1';
  if not RegQueryStringValue(HKCU, Key, 'UninstallString', Uninst) then
    if not RegQueryStringValue(HKLM, Key, 'UninstallString', Uninst) then
      Exit;
  Uninst := RemoveQuotes(Uninst);
  Exec(Uninst, '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART', '', SW_HIDE,
       ewWaitUntilTerminated, ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    UninstallPrevious();
end;
