$uri = 'http://www.cryptopp.com/cryptopp563.zip'

# Update this if needed
$MSBuild = 'C:\Program Files (x86)\MSBuild\14.0\Bin\MSBuild.exe'

if(!(Test-Path $MSBuild))
{
    Write-Host "Could not find MSBuild as"
    Write-Host "     $MSBuild"
    Write-Host ""
    Write-Host "Please update its lication in the script"



    exit
}
else
{
    #$version = (& $MSBuild /version) | Out-String
    #Write-Host $version
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

cd "$PWD\cryptopp"


& $MSBuild cryptest.sln  /p:Configuration=Release /p:Platform=x64
& $MSBuild cryptest.sln  /p:Configuration=Debug /p:Platform=x64






cd $startDir
