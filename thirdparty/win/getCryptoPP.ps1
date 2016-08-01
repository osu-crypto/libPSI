$uri = 'http://www.cryptopp.com/cryptopp563.zip'

# Update this if needed
$MSBuild = 'C:\Program Files (x86)\MSBuild\14.0\Bin\MSBuild.exe'
# 
if(!(Test-Path $MSBuild))
{
    Write-Host "Could not find MSBuild as"
    Write-Host "     $MSBuild"
    Write-Host ""
    Write-Host "Please update its lication in the script"

    exit
}

$DEVENV = "C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\IDE\devenv.exe"


if(!(Test-Path $DEVENV))
{
    Write-Host "Could not find devend.exe as"
    Write-Host "     $DEVENV"
    Write-Host ""
    Write-Host "Please update its lication in the script"

    exit
}

#cd 'C:\Users\peter\Source\Repos\mpsi\thirdparty\win'
$startDir = $PWD


$destination = "$PWD\cryptopp563.zip" 
 
if(!(Test-Path "$PWD\cryptopp"))
{

    
    if(!(Test-Path $destination))
    {
        Write-Host 'downloading ' $uri ' to ' $destination
        Write-Host 'It is 1.2 MB '

        Invoke-WebRequest -Uri $uri -OutFile $destination -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::internetexplorer

        Write-Host 'Download Complete'
    }

    Write-Host 'Extracting cryptopp563.zip to ' $PWD '.'

    Add-Type -assembly “system.io.compression.filesystem”
    [io.compression.zipfile]::ExtractToDirectory($destination, "$PWD\cryptopp")

    rm "$PWD\cryptopp563.zip"
     
}
else
{
    Write-Host "./cryptopp already exists. Skipping dowload and extract."
}


cp "$PWD\cryptopp_patch\*" "$PWD\cryptopp" -Force

cd "$PWD\cryptopp"


& $MSBuild cryptest.sln  /p:Configuration=Release /p:Platform=x64
& $MSBuild cryptest.sln  /p:Configuration=Debug /p:Platform=x64






cd $startDir
