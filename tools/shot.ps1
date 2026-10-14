Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class Win {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern void SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
}
"@

$want = $env:WANT_TITLE
$found = $null
$cb = [Win+EnumProc]{
  param($h, $l)
  if ([Win]::IsWindowVisible($h)) {
    $sb = New-Object System.Text.StringBuilder 512
    [void][Win]::GetWindowText($h, $sb, 512)
    $t = $sb.ToString()
    if ($want -and $t -like "*$want*") { $script:found = $h; return $false }
  }
  return $true
}
[void][Win]::EnumWindows($cb, [IntPtr]::Zero)

if ($found) {
  [Win]::ShowWindow($found, 3) | Out-Null
  [Win]::SetForegroundWindow($found) | Out-Null
  Write-Host "focused handle $found"
} else {
  Write-Host "NOT FOUND (want='$want') -- visible windows:"
  $cb2 = [Win+EnumProc]{
    param($h, $l)
    if ([Win]::IsWindowVisible($h)) {
      $sb = New-Object System.Text.StringBuilder 512
      [void][Win]::GetWindowText($h, $sb, 512)
      if ($sb.Length -gt 0) { Write-Host "  [$h] $($sb.ToString())" }
    }
    return $true
  }
  [void][Win]::EnumWindows($cb2, [IntPtr]::Zero)
}

Start-Sleep -Seconds 2
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$b = [System.Windows.Forms.SystemInformation]::VirtualScreen
$bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($b.Left, $b.Top, 0, 0, $bmp.Size)
$bmp.Save("$PSScriptRoot\_screen.png", [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Host "captured"