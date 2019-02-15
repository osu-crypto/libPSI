
$psi = New-Object System.Diagnostics.ProcessStartInfo;
$psi.FileName = "C:\Program Files (x86)\Pari64-2-9-4\gp.exe"; #process file
$psi.WorkingDirectory  = $pwd;
$psi.UseShellExecute = $false; #start the process from it's own executable file
$psi.RedirectStandardInput = $true; #enable the process to read from standard input

$p = [System.Diagnostics.Process]::Start($psi);

Start-Sleep -s 2 #wait 2 seconds so that the process can be up and running



		
For($nn = 16; $nn -lt 21; $nn= $nn + 4)
{
	for($mm = 12; $mm -lt 13; $mm = $mm + 2)
	{
		$n=  [math]::pow(2, $nn)
		$m = $n/$mm


		$p.StandardInput.WriteLine("n=$n;"); 
		$p.StandardInput.WriteLine("m=$m;"); 
		$p.StandardInput.WriteLine("\r C:/Users/Peter/repo/libPSI/libPSI/MPSI/Grr18/bayesian2.gp;"); 
	}
}


$p.StandardInput.WriteLine("quit");