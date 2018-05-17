
$psi = New-Object System.Diagnostics.ProcessStartInfo;
$psi.FileName = "gp.exe"; #process file
$psi.WorkingDirectory  = $pwd;
$psi.UseShellExecute = $false; #start the process from it's own executable file
$psi.RedirectStandardInput = $true; #enable the process to read from standard input

$p = [System.Diagnostics.Process]::Start($psi);

Start-Sleep -s 2 #wait 2 seconds so that the process can be up and running

$eps = 2;

For($nn = 10; $nn -lt 11; $nn= $nn + 4)
{
	for($mm = 4; $mm -lt 20; $mm = $mm + 2)
	{
		$n=  [math]::pow(2, $nn)
		$m = $n/$mm

		#& gp.exe < "n=$n; m=$mm; \\r./bayesian.gp;"

		$p.StandardInput.WriteLine("eps=$eps;"); 
		$p.StandardInput.WriteLine("n=$n;"); 
		$p.StandardInput.WriteLine("m=$m;"); 
		$p.StandardInput.WriteLine("\r C:/Users/Peter/repo/libPSI/libPSI/MPSI/Grr18/bayesian.gp;"); 
	}
}