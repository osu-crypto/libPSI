
# Update this if needed
$MSBuild = 'C:\Program Files (x86)\MSBuild\14.0\Bin\MSBuild.exe'
#$cl = 'C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\cl.exe'
$git = 'git'



if(!(Test-Path $MSBuild))
{
    Write-Host "Could not find MSBuild as"
    Write-Host "     $MSBuild"
    Write-Host ""
    Write-Host "Please update its lication in the script"

    exit
}
$uri = 'http://mpir.org/mpir-2.7.0.zip'
$zipFile = "$PWD/mpir-2.7.0.zip"
$startDir = $PWD
 
$folder =  "$PWD\mpir"
if(!(Test-Path $folder))
{

     
    if(!(Test-Path $zipFile))
    {
        Write-Host 'downloading ' $uri ' to ' $zipFile
        Write-Host 'It is 8.5 MB '

        Invoke-WebRequest -Uri $uri -OutFile $zipFile -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::internetexplorer

        Write-Host 'Download Complete'
    }

     
    Write-Host 'Extracting $zipFile to ' $PWD '. This will take a bit... So be patient.'


    Add-Type -assembly “system.io.compression.filesystem”
    [io.compression.zipfile]::ExtractToDirectory($zipFile, $PWD)

    mv "$PWD/mpir-2.7.0" $folder

    rm $zipFile
}
else
{
    Write-Host "$folder already exists. Skipping dowload and extract."
}


cp "$PWD\mpirxx.cpp" "$folder\mpirxx.cpp"

cd $folder/build.vc14

# NOTE: you can change this to your architecture for better performance
& $MSBuild lib_mpir_gc\lib_mpir_gc.vcxproj  /p:Configuration=Release /p:Platform=x64
& $MSBuild lib_mpir_gc\lib_mpir_gc.vcxproj  /p:Configuration=Debug /p:Platform=x64

# this is common to all CPUs
& $MSBuild lib_mpir_cxx\lib_mpir_cxx.vcxproj  /p:Configuration=Release /p:Platform=x64
& $MSBuild lib_mpir_cxx\lib_mpir_cxx.vcxproj  /p:Configuration=Debug /p:Platform=x64

echo ""
echo ""
echo "      A generic c implementation was built. Architecture specific builds are available. checkout ./mpir/build.vs14/* for more options." 
echo ""
echo ""

cd $startDir
