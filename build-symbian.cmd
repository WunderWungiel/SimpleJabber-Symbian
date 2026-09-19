@echo off
rem In-source Symbian build (Qt for Symbian supports only in-source; see SimpleOKM-Symbian).
rem   build-symbian.cmd            -> SimpleJabber.sis (self-signed, Belle)
rem   build-symbian.cmd installer  -> SimpleJabber_installer.sis (Smart Installer, Anna)
rem   build-symbian.cmd clean
setlocal
call D:\QtSDK\Symbian\SDKs\SymbianSR1Qt474\env.bat
cd /d %~dp0
if "%1"=="clean" ( call sbs -c arm.v5.urel.gcce4_4_1 clean & goto :eof )

rem Bump the patch version so each build produces a higher one (Symbian won't
rem downgrade). The installer variant wraps the same binary, so it does not bump again.
if not "%1"=="installer" python bump-version.py
qmake SimpleJabber.pro -spec symbian-sbsv2 CONFIG+=release
if errorlevel 1 exit /b 1
call sbs -c arm.v5.urel.gcce4_4_1
if errorlevel 1 exit /b 1
if "%1"=="installer" ( call createpackage.bat -i SimpleJabber_installer.pkg release-armv5 ) else ( call createpackage.bat SimpleJabber_template.pkg release-armv5 )

rem Stamp the version into the .sis name, e.g. SimpleJabber_1.0.2.sis.
for /f "delims=" %%v in ('python bump-version.py --print') do set VER=%%v
if "%1"=="installer" (
    if exist SimpleJabber_installer.sis ( copy /y SimpleJabber_installer.sis SimpleJabber_installer_%VER%.sis >nul & echo built SimpleJabber_installer_%VER%.sis )
) else (
    if exist SimpleJabber.sis ( copy /y SimpleJabber.sis SimpleJabber_%VER%.sis >nul & echo built SimpleJabber_%VER%.sis )
)
